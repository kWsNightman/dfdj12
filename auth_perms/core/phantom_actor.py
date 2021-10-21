"""
Phantom views for receiving information/changes from auth service and apply it on your service. All of methods are
could be used only if auth service sent this information.
"""
from flask import current_app as app
from flask import jsonify
from flask import make_response
from flask import request
from flask.views import MethodView
from flask_babel import gettext as _
from flask_cors import cross_origin

from .actions.phantom_actions import GetPhantomActorListAction
from .actions.phantom_actions import SetChosenPhantomActorAction
from .decorators import data_parsing
from .decorators import token_required
from .decorators import service_only
from .service_view import SendCallback
from .utils import get_current_actor
from .utils import create_response_message
from .utils import json_dumps
from .utils import verify_signature


class BasePhantomView:

    @staticmethod
    def verify_request_data():
        data = request.json
        signature = data.pop('signature')
        if not data or not signature:
            response = create_response_message(message=_("Invalid request data."), error=True)
            return response, True

        if not verify_signature(app.config['AUTH_PUB_KEY'], signature, json_dumps(data, sort_keys=True)):
            response = create_response_message(message=_("Signature verification failed."), error=True)
            return response, True

        return data, False


class GetPhantomActorView(MethodView):

    @cross_origin()
    @token_required
    def post(self):
        target_actor = get_current_actor(raise_exception=False)
        if not target_actor:
            response = create_response_message(message=_("There is no such actor"), error=True)
            return make_response(jsonify(response), 401)

        phantom_actors = GetPhantomActorListAction(target_actor=target_actor).get_phantom_actors()

        response = dict(
            actors=phantom_actors
        )
        return make_response(jsonify(response), 200)


class SetChosenPhantomActorView(MethodView):

    @cross_origin()
    @token_required
    @data_parsing
    def post(self, **kwargs):
        target_actor = get_current_actor(raise_exception=False)
        if not target_actor:
            response = create_response_message(message=_("There is no such actor"), error=True)
            return make_response(jsonify(response), 401)

        data = kwargs.get('data')

        if not data.get('uuid'):
            response = create_response_message(message=_("Invalid request data"), error=True)
            return make_response(jsonify(response), 400)

        response = SetChosenPhantomActorAction(phantom_uuid=data.get('uuid'),
                                               target_actor_uuid=target_actor.uuid).set_phantom_actor()
        if isinstance(response, dict) and response.get('error'):
            return make_response(jsonify(response), 400)

        return make_response(jsonify(response), 200)


class CreatePhantomRelationView(MethodView, BasePhantomView):

    @service_only
    @cross_origin()
    def post(self):
        """
        Create actor. Only for auth service.
        """
        data, error = self.verify_request_data()
        if error:
            return make_response(jsonify(data), 400)

        phantom_actor = data.get('phantom_actor')
        target_actor = data.get('target_actor')
        phantom_relation = data.get('phantom_relation')
        if not target_actor or not phantom_actor or not phantom_relation or \
                target_actor.get('uuid') != phantom_relation.get('target_actor') or \
                phantom_actor.get('uuid') != phantom_relation.get('phantom_actor'):
            response = create_response_message(message=_("Invalid request data."), error=True)
            return make_response(jsonify(response), 400)

        query = """INSERT INTO actor(uuid, root_perms_signature, initial_key, secondary_keys, uinfo, actor_type) 
        VALUES (%s, %s, %s, %s::jsonb, %s::jsonb, %s) ON CONFLICT (uuid) DO 
        UPDATE SET root_perms_signature=EXCLUDED.root_perms_signature, initial_key=EXCLUDED.initial_key, 
        secondary_keys=EXCLUDED.secondary_keys, uinfo=EXCLUDED.uinfo, actor_type=EXCLUDED.actor_type"""
        values = [phantom_actor.get('uuid'), phantom_actor.get('root_perms_signature'), phantom_actor.get('initial_key'),
                  json_dumps(phantom_actor.get('secondary_keys')), json_dumps(phantom_actor.get('uinfo')),
                  phantom_actor.get('actor_type')]
        app.db.execute(query, values)

        query = """INSERT INTO actor(uuid, root_perms_signature, initial_key, secondary_keys, uinfo, actor_type) 
        VALUES (%s, %s, %s, %s::jsonb, %s::jsonb, %s) ON CONFLICT (uuid) DO 
        UPDATE SET root_perms_signature=EXCLUDED.root_perms_signature, initial_key=EXCLUDED.initial_key, 
        secondary_keys=EXCLUDED.secondary_keys, uinfo=EXCLUDED.uinfo, actor_type=EXCLUDED.actor_type"""
        values = [target_actor.get('uuid'), target_actor.get('root_perms_signature'), target_actor.get('initial_key'),
                  json_dumps(target_actor.get('secondary_keys')), json_dumps(target_actor.get('uinfo')),
                  target_actor.get('actor_type')]
        app.db.execute(query, values)

        query = """INSERT INTO phantom_relation(uuid, phantom_actor, target_actor) VALUES (%s, %s, %s)"""
        values = [phantom_relation.get('uuid'), phantom_relation.get('phantom_actor'),
                  phantom_relation.get('target_actor')]
        app.db.execute(query, values)

        SendCallback(action_type='create_phantom_relation', data=phantom_relation).send_callback()
        response = dict(
            message=_("Phantom relation successfully created.")
        )
        return make_response(jsonify(response), 200)


class DeletePhantomRelationView(MethodView, BasePhantomView):

    @service_only
    @cross_origin()
    def post(self):
        """
        Delete actor. Only for auth service.
        """
        data, error = self.verify_request_data()
        if error:
            return make_response(jsonify(data), 400)

        if not data.get('uuid'):
            response = create_response_message(message=_("Invalid request data."), error=True)
            return make_response(jsonify(response), 400)

        query = """SELECT EXISTS(SELECT 1 FROM phantom_relation WHERE uuid = %s)"""
        if not app.db.fetchone(query, [data.get('uuid')]).get('exists'):
            response = dict(
                message=_("There is no such phantom relation.")
            )
            return make_response(jsonify(response), 200)

        query = """DELETE FROM phantom_relation WHERE uuid = %s"""
        values = [data.get('uuid')]
        app.db.execute(query, values)

        SendCallback(action_type='delete_phantom_relation', data=data).send_callback()
        response = dict(
            message=_("Phantom relation successfully deleted.")
        )
        return make_response(jsonify(response), 200)
