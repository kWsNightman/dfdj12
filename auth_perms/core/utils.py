import json
import hashlib
import random
import string
from flask import g
from flask_babel import gettext as _
from flask_babel import Locale
from datetime import date
from datetime import datetime
from datetime import time
from datetime import timedelta
from decimal import Decimal
from secrets import token_hex
from urllib.parse import urljoin
from uuid import UUID
from werkzeug.exceptions import Unauthorized

import requests
from email_validator import validate_email as email_validator_function
from email_validator import EmailNotValidError
from flask import request
from flask import session
from flask import current_app as app
from flask_babel import get_locale
from flask_socketio import emit

from .exceptions import Auth54ValidationError
from .exceptions import AuthServiceNotRegistered
from .mixins import UserMixin
from .mixins import AnonymousUserMixin
from .ecdsa_lib import sign_data
from .ecdsa_lib import verify_signature

KEY_CHARS = string.ascii_lowercase + string.ascii_uppercase + string.digits


class APIJSONEncoder(json.JSONEncoder):
    """
    Django's JSON encoder. Encoder for datetime objects, UUID and Decimal.
    """

    def default(self, obj):
        if isinstance(obj, datetime):
            rr = obj.isoformat()
            if obj.microsecond:
                rr = rr[:23] + rr[26:]
            if rr.endswith('+00:00'):
                rr = rr[:-6] + 'Z'
            return rr
        elif isinstance(obj, date):
            return obj.isoformat()
        elif isinstance(obj, time):
            if obj.utcoffset() is not None:
                raise ValueError(
                    'JSON can\'t represent timezone-aware times.')
            rr = obj.isoformat()
            if obj.microsecond:
                rr = rr[:12]
            return rr
        elif isinstance(obj, timedelta):
            return duration_iso_string(obj)
        elif isinstance(obj, (Decimal, UUID)):
            return str(obj)
        return super().default(obj)


def duration_iso_string(duration):
    """
    Django's helper function for proper translation of
    datetime.timedelta object into a string.
    """
    if duration < timedelta(0):
        sign = '-'
        duration *= -1
    else:
        sign = ''

    days, hours, mins, secs, msecs = _get_duration_components(
        duration)
    ms = '.{:06d}'.format(msecs) if msecs else ""
    return '{}P{}DT{:02d}H{:02d}M{:02d}{}S'.format(
        sign, days, hours, mins, secs, ms)


def _get_duration_components(duration):
    """
    Django's helper function for proper translation of
    datetime.timedelta object into a string.
    """
    days = duration.days
    seconds = duration.seconds
    microseconds = duration.microseconds

    minutes = seconds // 60
    seconds = seconds % 60

    hours = minutes // 60
    minutes = minutes % 60

    return days, hours, minutes, seconds, microseconds


def json_dumps(data, **kwargs):
    """
    Function like casual json.dumps, but using Django JSONEncoder upper as default class and passing all kwargs there.
    :param data: data for converting in the string
    :param kwargs: additional params
    :return: data in string format
    """
    return json.dumps(data, cls=APIJSONEncoder, **kwargs)


def json_encoder(obj):
    """
    Simple json encoder to prevent errors for the datetime objects passed to
    json.dumps.
    More complicated example of conversion could be found here:
    django/core/serializers/json.py.
    """
    if isinstance(obj, datetime):
        return obj.__str__()


def create_new_salt(user_info: dict, salt_for: str = None):
    """
    Generates a random salt and save it in database with uuid or public_key
    :param user_info: dictionary with key uuid or pub_key
    :param salt_for: string with argument what for we creating salt
    :return: salt: random generated hex string
    """
    salt = token_hex(16)

    if user_info.get('pub_key', None):
        if not is_valid_public_key(user_info.get('pub_key')):
            return None
        app.db.execute("INSERT INTO salt_temp(salt, pub_key, salt_for) VALUES (%s, %s, %s)",
                       [salt, user_info.get('pub_key'), salt_for])
    elif user_info.get('uuid', None):
        if not is_valid_uuid(user_info.get('uuid', None)):
            return None

        if not app.db.fetchone("""SELECT EXISTS(SELECT 1 FROM actor WHERE uuid = %s)""",
                               [user_info.get('uuid')]).get('exists'):
            # local import only
            from .service_view import GetAndUpdateActor
            actor = GetAndUpdateActor(uuid=user_info.get('uuid')).update_actor()
            if not actor:
                return None

        app.db.execute("INSERT INTO salt_temp(salt, uuid, salt_for) VALUES (%s, %s::uuid, %s)",
                       [salt, user_info.get('uuid'), salt_for])
    elif user_info.get('qr_token', None):
        app.db.execute("INSERT INTO salt_temp(salt, qr_token, salt_for) VALUES (%s, %s, %s)",
                       [salt, user_info.get('qr_token'), salt_for])
    else:
        return None

    return salt


def get_user_salt(user_info: dict, salt_for: str = None):
    """
    Get salt that was sent to user to sign
    :param user_info: dictionary with key uuid or pub_key
    :param salt_for:  string with argument what for we creating salt
    :return: salt or None if not exists row
    """

    if user_info.get('qr_token', None):
        salt = app.db.fetchone("""SELECT salt FROM salt_temp WHERE qr_token = %s AND uuid = %s AND salt_for=%s AND 
        created > timezone('utc', now()) ORDER BY created DESC LIMIT 1""",
                               [user_info.get('qr_token'), user_info.get('uuid'), salt_for])
        if not salt:
            salt = app.db.fetchone("""SELECT salt FROM salt_temp WHERE qr_token = %s AND uuid IS NULL AND salt_for=%s 
            AND created > timezone('utc', now()) ORDER BY created DESC LIMIT 1""",
                                   [user_info.get('qr_token'), salt_for])

            if not salt:
                return None

        return salt.get('salt')

    elif user_info.get('pub_key', None):
        if not is_valid_public_key(user_info.get('pub_key')):
            return None

        query ="""SELECT salt FROM salt_temp WHERE pub_key=%s AND salt_for=%s 
        AND created > timezone('utc', now()) ORDER BY created DESC LIMIT 1"""
        values = [user_info.get('pub_key'), salt_for]
    elif user_info.get('uuid', None):
        if not is_valid_uuid(user_info.get('uuid', None)):
            return None

        query = """SELECT salt FROM salt_temp WHERE uuid=%s::uuid AND salt_for=%s 
        AND created > timezone('utc', now()) ORDER BY created DESC LIMIT 1"""
        values = [user_info.get('uuid'), salt_for]
    else:
        return None

    salt = app.db.fetchone(query, values)
    if not salt:
        return None

    return salt.get('salt')


def delete_salt(user_info: dict):
    """
    Delete salt if it was used.
    :param user_info: dictionary with key uuid or pub_key
    :return: True if deleted, False if not
    """

    if user_info.get('pub_key', None):
        query = "DELETE FROM salt_temp WHERE pub_key=%s RETURNING salt"
        values = [user_info.get('pub_key')]
    elif user_info.get('uuid', None):
        query = "DELETE FROM salt_temp WHERE uuid=%s RETURNING salt"
        values = [user_info.get('uuid')]
    elif user_info.get('qr_token', None):
        query = "DELETE FROM salt_temp WHERE qr_token=%s RETURNING salt"
        values = [user_info.get('qr_token')]
    else:
        return False

    salt = app.db.fetchall(query, values)

    if not salt:
        return None

    return True


def update_salt_data(uuid: str, qr_token: str):
    """
    Update salt with setting actor uuid in database.
    :param uuid: actor uuid
    :param qr_token: qr token
    :return: updated salt or None
    """

    if app.db.fetchone("""SELECT EXISTS(SELECT 1 FROM actor WHERE uuid = %s)""", [uuid]).get('exists'):

        salt = app.db.fetchone("""UPDATE salt_temp SET uuid = %s WHERE qr_token = %s RETURNING *""", [uuid, qr_token])

        if not salt:
            return None

        return salt

    return None


def is_valid_uuid(uuid: str, version: int = None):
    """
    Check if uuid is valid UUID
    :param uuid: string uuid on test
    :param version: uuid version
    :return: True if valid else False
    """
    if not isinstance(uuid, str):
        try:
            uuid = str(uuid)
        except Exception as e:
            print('Error while converting uuid in string')
            return False

    if version:
        try:
            uuid_obj = UUID(uuid, version=version)
        except (AttributeError, ValueError, TypeError):
            return False

        return str(uuid_obj) == uuid

    check_result = None
    for version in range(1, 6):
        try:
            uuid_obj = UUID(uuid, version=version)
        except (AttributeError, ValueError, TypeError):
            continue

        check_result = str(uuid_obj) == uuid
        if not check_result:
            continue
        else:
            return check_result

    return check_result


def is_valid_public_key(public_key: str):
    """
    Check if public key is valid by length and prefix
    :param public_key: string public key
    :return: True if valid else False
    """
    # Public key length if we using coordinates (04 prefix) is 130
    # symbols.
    if len(public_key) != 130:
        return False

    # Check whether public key contains hex characters only
    if not all(c in string.hexdigits for c in public_key):
        return False

    # We should check on 04 prefix cause ecdsa public key with
    # Elliptic Curve starts with prefix 04
    if not public_key.startswith('04'):
        return False
    return True


def get_public_key(uuid: str):
    """
    Getting user public key
    :param uuid: user uuid
    :return: initial_key, secondary keys: initial_key - primary user public key
    saved in registration process (PRIMARY), secondary_key - list of generated
    user public keys
    """
    secondary_keys = None
    data = app.db.fetchone("SELECT initial_key, secondary_keys FROM actor WHERE uuid=%s", [uuid])

    if not data:
        # Such user does not exists
        return None, None
    if data.get('secondary_keys'):
        secondary_keys = data.get('secondary_keys').values()

    initial_key = data.get('initial_key')
    return initial_key, secondary_keys


def get_apt54(uuid: str):
    """
    Send POST request on auth for getting apt54
    :param uuid: user uuid
    :return: apt54 or None
    """
    url = urljoin(get_auth_domain(), '/get_apt54/')
    data = dict(
        uuid=uuid,
        service_uuid=app.config['SERVICE_UUID']
    )
    data['signature'] = sign_data(app.config['SERVICE_PRIVATE_KEY'], json_dumps(data, sort_keys=True))
    try:
        response = requests.post(url, json=data, headers=get_language_header())
    except Exception as e:
        print('Auth is unreachable')
        return None, 500

    data = json.loads(response.content)
    if response.ok:
        if verify_apt54(data):
            return data, response.status_code

    return data, response.status_code


def get_apt54_locally(uuid: str):
    """
    Build apt54 locally
    :param uuid:
    :return: apt54 or None
    """
    from .actor import Actor
    from .actor import ActorNotFound
    try:
        actor = Actor.objects.get(uuid=uuid)
    except ActorNotFound:
        return None, 452

    data = json_dumps(actor.to_dict(), sort_keys=True)
    expiration = datetime.strftime(datetime.utcnow() + timedelta(days=14),
                                   '%Y-%m-%d %H:%M:%S')
    signature = sign_data(app.config['SERVICE_PRIVATE_KEY'], data + expiration)
    response = dict(
        user_data=json.loads(data),
        expiration=expiration,
        signature=signature
    )
    return response, 200


def generate_random_string(charset=KEY_CHARS, length=32):
    """
    Generates random string.
    :param charset: string of characters for generating
    :param length: int. length of result sting
    :return: string
    """
    return ''.join(random.choice(charset) for i in range(length))


def create_session(apt54: dict, auxiliary_token: str = '', service_uuid: str = '', depended_info={}):
    """
    Session generation on service
    :param apt54: dict. User's apt54
    :param auxiliary_token: string value of generated for salt qr or salt if sso
    :param service_uuid: target service uuid fir what session_token is creating
    :return: session_token: str. Service session token
    """
    # Local import only
    from .actor import Actor
    if not service_uuid:
        service_uuid = app.config['SERVICE_UUID']

    uuid = apt54['user_data'].get('uuid') if apt54.get('user_data') else apt54.get('uuid')
    actor = Actor.objects.get(uuid=uuid)
    # Return error response message if user is banned.
    if actor.is_banned:
        response = create_response_message(message=_("You are in ban group. "
                                                     "Please contact the administrator to set you role."), error=True)
        return response

    # Session creating
    while True:
        session_token = dict(
            session_token=generate_random_string(KEY_CHARS)
        )

        if app.db.fetchone("""SELECT EXISTS(SELECT 1 FROM service_session_token WHERE session_token=%s)""",
                           [session_token.get("dession_token")]).get('exists'):
            continue

        app.db.execute("""INSERT INTO service_session_token(session_token, uuid, apt54, auxiliary_token, service_uuid) 
        VALUES (%s, %s, %s, %s, %s)""", [session_token.get("session_token"), uuid, json_dumps(apt54), auxiliary_token, service_uuid])
        sid = get_user_sid(auxiliary_token)
        if sid:
            if depended_info:
                make_session_in_depended_services(depended_info, session_token)
            emit('authorization response', session_token, room=sid, namespace='/')

        return session_token.get("session_token")


def make_session_in_depended_services(depended_info, session_token):
    for name, service_data in depended_info.items():
        session_token.update({name + "_session_token": dict(requests.post(
            app.config.get("DEPENDED_SERVICES").get(
                name.lower()
            ) + "/auth/",
            json=service_data
        ).json()).get("session_token")}
        )


def get_session_token():
    """
    Get session token from request.
    :return: session_token or None in case if session_token is not present in cookies or request
    """

    session_token = None
    if 'Session-Token' in request.headers or 'session_token' in session:
        session_token = request.headers.get('Session-Token')
        if not session_token:
            session_token = session.get('session_token')

    return session_token


def get_session(session_token: str):
    """
    Get session by session_token
    :param session_token: token of the session
    :return: session object if exists
    """
    service_session_token= app.db.fetchone("""SELECT * FROM service_session_token WHERE session_token=%s""",
                                           [session_token])

    return service_session_token


def get_session_token_by_auxiliary(auxiliary_token: str = None):
    """
    Get session by auxiliary_token.
    :param auxiliary_token: string. Some token which we use to save session. Example: QR token = auxiliary token.
    :return: session
    """
    service_session_token = app.db.fetchone("""SELECT session_token FROM service_session_token 
    WHERE auxiliary_token=%s""", [auxiliary_token])

    return service_session_token


def verify_apt54(apt54: dict):
    """
    APT54 verification that user received it from auth and didn't change any data
    :param apt54: user APT54
    :return: verification result. True - verification passed, False - verification failed
    """
    signature = apt54.get('signature')
    user_data = json_dumps(apt54.get('user_data'), sort_keys=True)
    data = str(user_data) + str(apt54.get('expiration'))
    if app.config['AUTH_STANDALONE']:
        if not verify_signature(app.config['SERVICE_PUBLIC_KEY'], signature, data):
            return False
    else:
        if not verify_signature(app.config['AUTH_PUB_KEY'], signature, data):
            return False
    return True


def check_if_auth_service():
    """
    Checks if service auth or not.
    :return: boolean value. True - if service auth, False - if not
    """
    salt = token_hex(16)
    signature = sign_data(app.config['SERVICE_PRIVATE_KEY'], salt)
    if app.config['AUTH_STANDALONE']:
        if not verify_signature(app.config['SERVICE_PUBLIC_KEY'], signature, salt):
            return False
    else:
        if not verify_signature(app.config['AUTH_PUB_KEY'], signature, salt):
            return False
    return True


def apt54_expired(expiration: str):
    """
    Check if apt54 expired
    :param expiration: apt54 expiration
    :return: True if expired, False if not
    """
    if datetime.utcnow() > datetime.strptime(expiration, '%Y-%m-%d %H:%M:%S'):
        return True
    return False


def actor_exists(uuid: str):
    """
    Check if user exists on service
    :param uuid: user uuid we need to check
    :return: True if exists, False if not
    """
    # Check if user exists on service
    if app.db.fetchone("""SELECT EXISTS(SELECT 1 FROM actor WHERE uuid=%s)""", [uuid]).get('exists'):
        return True

    return False


def create_actor(apt54: dict):
    """
    Create actor on client service
    :param apt54: user apt54
    :return: actor if created or None if not
    """
    data = apt54.get('user_data')
    query = """INSERT INTO actor SELECT * FROM jsonb_populate_record(null::actor, jsonb %s::jsonb) RETURNING uuid"""
    values = [json_dumps(data)]
    try:
        actor_uuid = app.db.fetchone(query, values)
        query = """SELECT * FROM actor WHERE uuid = %s"""
        values = [actor_uuid.get('uuid')]
        actor = app.db.fetchone(query, values)
    except Exception as e:
        print('Exception on creating actor! %s' % e)
        actor = None

    return actor


def update_user(apt54: dict):
    """
    Update user on client service
    :param apt54: user apt54
    """
    data = apt54.get('user_data')
    app.db.execute("""UPDATE actor SET uinfo = actor.uinfo::jsonb || %s::jsonb, initial_key = %s, secondary_keys = %s 
    WHERE actor.uuid = %s""", [json_dumps(data.get('uinfo')), data.get('initial_key'), data.get('secondary_keys'),
                               data.get('uuid')])


def create_response_message(message, error=False):
    """
    Create response dict with error status and just information message
    :param message: message text
    :param error: boolean flag. True - error message, False - information message
    :return: dict
    """
    if error:
        response = dict(
            error=True,
            error_message=message
        )
    else:
        response = dict(
            message=message
        )
    return response


def get_default_user_group():
    """
    Get default user group. By default user adds in this group
    :return: group
    """
    group = app.db.fetchone("""SELECT * FROM actor WHERE actor_type='group' AND uinfo->>'group_name'=%s""",
                            [app.config.get('DEFAULT_GROUP_NAME')])
    return group


# TODO: choose between this variant or .managers UserManager
def user_context_processor():
    # Local import only
    from .actor import Actor
    from .actor import ActorNotFound

    session_token = None
    if app.config.get('SESSION_STORAGE'):
        if app.config.get('SESSION_STORAGE') == 'HEADERS':
            session_token = request.headers.get('Session-Token', None)
        elif app.config.get('SESSION_STORAGE') == 'SESSION':
            session_token = session.get('session_token', None)
    else:
        if 'Session-Token' in request.headers or 'session_token' in session:
            session_token = request.headers.get('Session-Token')
            if not session_token:
                session_token = session.get('session_token')

    if session_token:
        try:
            user = Actor.objects.get_by_session(session_token=session_token)
        except ActorNotFound:
            return dict(current_user=AnonymousUserMixin())

        if user:
            return dict(current_user=UserMixin(user.to_dict()))

    return dict(current_user=AnonymousUserMixin())


def generate_qr_token():
    """
    Generate random qr token
    :return: string
    """
    return generate_random_string(KEY_CHARS)


def get_static_group(group_name: str):
    """
    Get BAN or ADMIN or DEFAULT group.
    :param group_name: group name (BAN or ADMIN or DEFAULT)
    :return: group_uuid
    """
    group = app.db.fetchone("""SELECT uuid FROM actor WHERE actor_type='group' AND uinfo->>'group_name'=%s""",
                            [group_name])
    return group


def validate_email(email: str) -> None:
    """
    Validate passed email value.
    """
    try:
        valid = email_validator_function(email)
    except EmailNotValidError as e:
        print(str(e))
        raise Auth54ValidationError('Invalid email')


def get_user_mixin():
    """
    Get original or redefined UserMixin implementation.
    """
    if 'USER_MIXIN' not in app.config:
        raise KeyError(
            'To use get_user_mixin function USER_MIXIN path '
            'should be defined in the application\'s config '
            'as a tuple in format '
            '(\'path.to.module\', \'MixinName\').'
        )
    return getattr(
        __import__(app.config['USER_MIXIN'][0], fromlist=[None]),
        app.config['USER_MIXIN'][1]
    )


def get_user_sid(qr_token: str):
    """
    Get user sid by qr token
    :param qr_token: qr token
    :return: sid
    """
    sid = app.db.fetchone("""SELECT actor_sid FROM salt_temp WHERE qr_token = %s""", [qr_token])

    if not sid:
        return None

    return sid.get('actor_sid')


def hash_md5(text: str):
    """
    Hash string with md5. Need for hashing password and password verification
    :param text: string
    :return: hashed string
    """
    hasher = hashlib.md5()
    hasher.update(text.encode('utf-8'))
    text = hasher.hexdigest()
    return text


def create_temporary_session():
    """
    Create temporary session. Need for saving in cookies before redirect on auth.
    :return: temporary_session
    """
    while True:
        temporary_session = generate_random_string(KEY_CHARS)

        if app.db.fetchone("""SELECT EXISTS(SELECT 1 FROM temporary_session WHERE temporary_session=%s)""",
                           [temporary_session]).get('exists'):
            continue

        app.db.execute("""INSERT INTO temporary_session(temporary_session, service_uuid) VALUES (%s, %s)""",
                       [temporary_session, app.config['SERVICE_UUID']])

        return temporary_session


def get_temporary_session_token():
    """
    Get temporary session token from cookies.
    :return: temporary_session_token
    """
    return request.cookies.get('temporary_session', None)


def get_temporary_session():
    """
    Get temporary session info from database
    :return: temporary_session
    """
    temporary_session_token = get_temporary_session_token()
    if not temporary_session_token:
        return None

    temporary_session = app.db.fetchone("""SELECT * FROM temporary_session WHERE temporary_session = %s 
    ORDER BY created DESC LIMIT 1 """, [temporary_session_token])

    return temporary_session


def delete_temporary_session(temporary_session: str = None):
    """
    Delete temporary session from database
    :return: None
    """
    if not temporary_session:
        temporary_session = get_temporary_session()

    app.db.execute("DELETE FROM temporary_session WHERE temporary_session = %s", [temporary_session])


def delete_old_permissions(service_id, permissions):
    """
    Call psql function for deleting permissions that not exists in permissions variable.
    :param service_id: uuid. current service uuid
    :param permissions: list. list of dicts with permission information
    :return: None
    """
    if not app.db.fetchone("""SELECT EXISTS(SELECT 1 FROM actor WHERE actor_type = 'service' AND uuid = %s)""",
                           [service_id]).get('exists'):
        return

    app.db.execute("SELECT delete_old_permissions(%s, %s)", [service_id, json_dumps(permissions)])

    return


def get_auth_domain():
    """
    Get auth domain from database using AUTH PUBLIC KEY.
    :return: string
    """
    query = "SELECT uinfo->>'service_domain' AS service_domain FROM actor WHERE initial_key = %s"
    if app.config['AUTH_STANDALONE']:
        values = [app.config['SERVICE_PUBLIC_KEY']]
    else:
        values = [app.config['AUTH_PUB_KEY']]
    domain = app.db.fetchone(query, values)
    if not domain:
        raise AuthServiceNotRegistered

    return domain.get('service_domain')


def print_error_cli(message: str = 'Some error occurred.', status: int = 400):
    """
    Print some error in console.
    :param message: message to write
    :param status: error status
    :return: None
    """
    print('-' * 35, 'ERROR %s' % status, '-' * 35)
    print(message)
    return


def set_actor_sid(sid, data):
    """
    Save actor sid (socket id) for exact QR. And update old salt information with this QR.
    :param sid: socket id
    :param data: dict. Data that helps get salt information. Example qr_token.
    :return:
    """
    query = """SELECT salt, salt_for FROM salt_temp WHERE qr_token = %s ORDER BY created DESC"""
    salt_list = app.db.fetchall(query, [data.get('qr_token')])
    if salt_list:
        last_salt = salt_list[0]
    else:
        return

    if len(salt_list) > 1:
        query = """DELETE FROM salt_temp WHERE qr_token = %s AND salt != %s AND salt_for=%s AND actor_sid IS NULL"""
        app.db.execute(query, [data.get('qr_token'), last_salt.get('salt'), last_salt.get('salt_for')])

    if last_salt:
        query = """DELETE FROM salt_temp WHERE actor_sid = %s AND salt != %s AND salt_for = %s"""
        app.db.execute(query, [sid, last_salt.get('salt'), last_salt.get('salt_for')])
        query = """UPDATE salt_temp SET actor_sid = %s WHERE qr_token = %s"""
        app.db.execute(query, [sid, data.get('qr_token')])


def get_service_locale():
    """
    Get locale code that service is using for this user by request.
    :return: string
    """
    try:
        locale = get_locale()
    except TypeError as e:
        print('Error with getting locale - %s' % str(e))
        locale = request.cookies.get(app.config.get('LANGUAGE_COOKIE_KEY', None))
        if not locale or locale not in app.config.get('LANGUAGES', ['en', 'ru']):
            locale = request.accept_languages.best_match(app.config.get('LANGUAGES', ['en', 'ru']))
    except Exception as e:
        print('Exception with getting locale - %s' % str(e))
        locale = 'en'

    return locale.language if isinstance(locale, Locale) else str(locale)


def get_language_header():
    """
    Create custom header with setting locale for requests on other services and receiving messages in set language
    :return: dict
    """
    return {"Http-Accept-Language": get_service_locale()}


def get_current_actor(raise_exception=True):
    """
    Get current actor from g or by session token or raise Unauthorized
    :param raise_exception: bool. Should service raise Unauthorized if there is no such actor.
    :return: actor or None or raise exception
    """
    from .actor import Actor
    from .actor import ActorNotFound

    if hasattr(g, 'actor'):
        return getattr(g, 'actor')

    session_token = get_session_token()
    if not session_token and not raise_exception:
        return None

    try:
        actor = Actor.objects.get_by_session(session_token=session_token)
        return actor
    except ActorNotFound:
        if not raise_exception:
            return None

    raise Unauthorized
