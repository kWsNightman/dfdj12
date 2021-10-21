"""
Actor views for receiving information/changes from auth service and apply it on your service. All of methods are
could be used only if auth service sent this information.
"""
from flask import current_app as app
from flask import jsonify
from flask import make_response
from flask import request

from flask.views import MethodView
from flask_babel import gettext as _
from flask_cors import cross_origin

from psycopg2 import errors
from uuid import uuid4
from uuid import UUID

from .decorators import service_only
from .ecdsa_lib import verify_signature
from .service_view import SendCallback
from .utils import create_response_message
from .utils import json_dumps
from .utils import hash_md5
from .utils import validate_email
from .actor import Actor
from .actor import ActorNotFound
from .auth_view import RegistrationView
from .exceptions import Auth54ValidationError


class BaseActorView:

    @staticmethod
    def verify_request_data():
        data = request.json
        signature = data.pop("signature")
        if not data or not signature:
            response = create_response_message(message=_("Invalid request data."), error=True)
            return response, True

        if not verify_signature(app.config['AUTH_PUB_KEY'], signature, json_dumps(data, sort_keys=True)):
            response = create_response_message(message=_("Signature verification failed."), error=True)
            return response, True

        return data, False


class ActorView(MethodView, BaseActorView):

    @service_only
    @cross_origin()
    def post(self):
        """
        Create actor. Only for auth service.
        """
        data, error = self.verify_request_data()
        if error:
            return make_response(jsonify(data), 400)

        actor = data.get('actor')

        query = """INSERT INTO actor (SELECT * FROM jsonb_populate_record(null::actor, jsonb %s)) RETURNING uuid"""
        values = [json_dumps(actor)]
        actor_uuid = app.db.fetchone(query, values)
        if not actor_uuid:
            response = create_response_message(message=_("Some error occurred while creating actor."), error=True)
            return make_response(jsonify(response), 400)

        SendCallback(action_type='create_actor', data=actor).send_callback()
        response = dict(
            message=_("Actor was successfully created.")
        )
        return make_response(jsonify(response), 200)

    @service_only
    @cross_origin()
    def put(self):
        """
        Update actor. Only for auth service.
        """
        data, error = self.verify_request_data()
        if error:
            return make_response(jsonify(data), 400)

        app.db.execute("SELECT update_or_insert_actor_if_group_exists(%s)", [json_dumps(data.get('actors'))])

        data = dict(
            object_uuid=data.get('object_uuid')
        )
        SendCallback(action_type='update_actor', data=data).send_callback()
        response = dict(
            message=_("Actor was successfully updated.")
        )
        return make_response(jsonify(response), 200)

    @service_only
    @cross_origin()
    def delete(self):
        """
        Delete actor. Only for auth service
        """

        data, error = self.verify_request_data()
        if error:
            return make_response(jsonify(data), 400)

        actor = data.get('actor')
        if actor.get('actor_type') == 'group':
            # Delete this group for users in uinfo.groups
            app.db.execute("""UPDATE actor SET uinfo = jsonb_set(uinfo, '{groups}', ((uinfo->'groups')::jsonb - %s)) 
            WHERE uinfo->'groups' ? %s AND actor_type='user'""", [actor.get('uuid'), actor.get('uuid')])

        app.db.execute("""DELETE FROM actor WHERE uuid=%s""", [actor.get('uuid')])

        SendCallback(action_type='delete_actor', data=actor).send_callback()
        response = dict(
            message=_("Actor was successfully deleted.")
        )
        return make_response(jsonify(response), 200)

    @staticmethod
    def create_actor(actor):
        """
        Create actor for standalone mode.
        """
        uinfo = actor.get('uinfo')
        actor['uuid'] = uuid4()

        if actor.get('actor_type') == 'classic_user':

            if not uinfo.get('email') or not uinfo.get('password'):
                response = create_response_message(message=_("Invalid request data."), error=True)
                return response, 400

            if uinfo.get('email'):
                if app.db.fetchone("""SELECT EXISTS(SELECT 1 FROM actor WHERE uinfo ->> 'email' = %s)""",
                                   [uinfo.get('email')]).get('exists'):
                    response = create_response_message(message=_("Actor with such email already exists."), error=True)
                    return response, 400

                try:
                    validate_email(uinfo.get('email'))
                except Auth54ValidationError as e:
                    response = create_response_message(
                        message=_("Email you have inputted is invalid. Please check it."),
                        error=True)
                    return response, 400

            if len(uinfo.get('groups')) == 0:
                uinfo = RegistrationView.add_default_group(actor)
            else:
                for group in uinfo.get('groups'):
                    try:
                        UUID(group)
                    except ValueError:
                        response = create_response_message(message=_("Invalid group uuid %(group)s",
                                                                     group=group), error=True)
                        return response, 400

            uinfo['password'] = hash_md5(uinfo.get('password'))

        elif actor.get('actor_type') == 'group':

            uinfo['group_name'] = uinfo.get('group_name').upper()
            uinfo['weight'] = int(uinfo.get('weight'))

            if uinfo.get('group_name'):
                if app.db.fetchone("""SELECT EXISTS(SELECT 1 FROM actor WHERE uinfo ->> 'group_name' = %s)""",
                                   [uinfo.get('group_name')]).get('exists'):
                    response = create_response_message(message=_("Group with such name already exists."), error=True)
                    return response, 400

            users = uinfo.pop('users')

            if len(users) != 0:
                query = """UPDATE actor SET uinfo = jsonb_set(uinfo, '{groups}', uinfo->'groups' || %s) WHERE actor_type
                           IN ('user', 'classic_user') AND NOT uinfo->'groups' @> %s AND uuid IN %s;"""
                app.db.execute(query, [json_dumps([actor.get('uuid')]), json_dumps([actor.get('uuid')]), tuple(users)])

        else:
            response = create_response_message(message=_("Invalid actor type %(actor_type)s",
                                                         actor_type=actor.get('actor_type')), error=True)
            return response, 400

        query = """INSERT INTO actor (SELECT * FROM jsonb_populate_record(null::actor, jsonb %s)) RETURNING uuid"""

        values = [json_dumps(actor)]
        actor_uuid = app.db.fetchone(query, values)

        if not actor_uuid:
            response = create_response_message(message=_("Some error occurred while creating actor."), error=True)
            return response, 400
        response = dict(
            message=_("Actor was successfully created.")
        )
        return response, 200

    @staticmethod
    def delete_actor(uuid):
        """
        Delete actor for standalone mode.
        """
        try:
            actor = Actor.objects.get(uuid=uuid)
        except ActorNotFound:
            response = create_response_message(message='No actor with such uuid found', error=True)
            return response, 400
        except errors.InvalidTextRepresentation:
            response = create_response_message(message='Invalid uuid', error=True)
            return response, 400

        if actor.actor_type == 'group':
            app.db.execute("""UPDATE actor SET uinfo = jsonb_set(uinfo, '{groups}', ((uinfo->'groups')::jsonb - %s)) 
                        WHERE uinfo->'groups' ? %s AND actor_type IN ('user', 'classic_user')""",
                           [uuid, uuid])
        app.db.execute("""DELETE FROM actor WHERE uuid=%s""", [uuid])
        response = create_response_message(message='Actor was successfully deleted')
        return response, 200
