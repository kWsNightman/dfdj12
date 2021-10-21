import requests
from flask_socketio import emit
from flask import request
from flask import current_app as app
from flask_babel import gettext as _
from werkzeug.exceptions import Forbidden
from werkzeug.exceptions import Unauthorized

from .actions.phantom_actions import GetPhantomActorListAction
from .actor import Actor
from .actor import ActorNotFound
from .ecdsa_lib import verify_signature
from .utils import delete_temporary_session
from .utils import get_session_token_by_auxiliary
from .utils import get_session_token
from .utils import set_actor_sid
from . import socketio

try:
    from service54.settings import DEPENDED_SERVICES
except ImportError:
    try:
        from auth54.settings import DEPENDED_SERVICES
    except ImportError:
        try:
            from settings import DEPENDED_SERVICES
        except ImportError:
            pass



@socketio.on('connect')
def connect():
    emit('authorization response', {'data': 'Connected'})


@socketio.on('authorization')
def authorization(data):
    """
    This method is used to save user socket id for sending session token on it when it will be generated.
    Temporary session is used for getting session with auth single sign on. It means that session on current service
    will be generated based on auth session.
    :param data: dict with params (qr_token or temporary_session)
    :return: message in socket.
    """
    if data.get('qr_token'):
        session_token = get_session_token_by_auxiliary(data.get('qr_token'))
        if not session_token:
            if hasattr(request, 'sid'):
                sid = request.sid
            else:
                response = dict(
                    message=_("Some error occurred while getting socket id.")
                )
                emit('authorization response', response, broadcast=False)
                return

            set_actor_sid(sid, data)

            response = dict(
                message=_("There is no session token.")
            )
            emit('authorization response', response, broadcast=False)
            return

        for name, service_data in data.get("depended_services").items():
            session_token.update({name + "_session_token": dict(requests.post(
                DEPENDED_SERVICES.get(
                    name.lower()
                ) + "/get_session/",
                json=service_data
            ).json()).get("session_token")}
            )

        emit('authorization response', session_token, broadcast=False)

    temporary_sessions = {key: value for key,
                          value in data.items() if "temporary" in key}
    if temporary_sessions:
        if temporary_sessions.get('temporary_session', None):
            temporary_session = temporary_sessions.pop('temporary_session')
            if app.db.fetchone("""SELECT EXISTS(SELECT 1 FROM temporary_session WHERE temporary_session = %s)""",
                               [temporary_session]).get('exists'):
                session_token = get_session_token_by_auxiliary(
                    temporary_session)
                if session_token:
                    app.db.execute("""UPDATE service_session_token SET auxiliary_token = NULL WHERE auxiliary_token = %s""",
                                   [temporary_session])
                    session_token = dict(session_token)

                    delete_temporary_session(temporary_session)
                else:
                    session_token = dict()

                for name, temporary_session in temporary_sessions.items():
                    service_name = name.replace("temporary_session_", "")
                    session_token.update({service_name + "_session_token": dict(requests.post(
                        DEPENDED_SERVICES.get(
                            service_name
                        ) + "/get_session/",
                            json={"temporary_session": temporary_session}
                    ).json()).get("session_token")}
                    )
                emit('authorization response', session_token, broadcast=False)


@socketio.on('auth_sso')
def auth_sso(data):
    """
    Get session token after back redirect from auth single sign on.
    :param data: dict with salt from auth and signature.
    :return: message on socket
    """
    if not data.get('salt', None) or not data.get('signature', None):
        response = dict(
            message=_("Invalid request data.")
        )
        emit('auth_sso response', response, broadcast=False)
        return

    signature = data.pop('signature')
    salt = data.get('salt', None)
    if not verify_signature(app.config['AUTH_PUB_KEY'], signature, salt):
        response = dict(
            message=_("Signature verification failed.")
        )
        emit('auth_sso response', response, broadcast=False)
        return

    session_token = get_session_token_by_auxiliary(data.get('salt'))
    if session_token:
        app.db.execute("""UPDATE service_session_token SET auxiliary_token = NULL""")

    emit('auth_sso response', session_token, broadcast=False)


@socketio.on('verify', namespace='/phantom')
def verify_phantom(msg=None):
    """
    Verify if actor could use phantom actor
    """
    try:
        sid = request.sid
    except Exception as e:
        print('There is no socket id in verify phantom')
        return

    session_token = get_session_token()
    if not session_token:
        emit('verification_result', {"result": False}, room=sid, namespace="/phantom", broadcast=False)
        return

    try:
        actor = Actor.objects.get_by_session(session_token=session_token)
    except ActorNotFound:
        emit('verification_result', args={"result": False}, room=sid, namespace="/phantom", broadcast=False)
        return

    try:
        actors = GetPhantomActorListAction(target_actor=actor).get_phantom_actors()
    except Forbidden:
        emit('verification_result', {"result": False}, room=sid, namespace="/phantom", broadcast=False)
        return
    except Unauthorized:
        emit('verification_result', {"result": False}, room=sid, namespace="/phantom", broadcast=False)
        return

    emit("verification_result", {"result": True, "actors": actors}, room=sid,  namespace="/phantom", broadcast=False)
    return


@socketio.on('logout', namespace='/phantom')
def logout_phantom(msg=None):
    """
    Logout phantom actor
    """
    session_token = get_session_token()
    if not session_token:
        return

    actor = Actor.objects.get_by_session(session_token=session_token)

    if actor.actor_type == 'phantom':
        query = """DELETE FROM service_session_token WHERE session_token=%s AND uuid = %s"""
        app.db.execute(query, [session_token, actor.uuid])

    return
