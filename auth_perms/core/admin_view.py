from flask import jsonify
from flask import make_response
from flask import current_app as app
from flask import render_template
from flask import request
from flask import redirect
from flask import url_for
from flask import session
from flask.views import MethodView
from flask.views import View
from flask_cors import cross_origin

from werkzeug.exceptions import NotFound
from psycopg2 import errors

from .actor import Actor
from .actor import ActorNotFound
from .utils import json_dumps
from .utils import hash_md5
from .utils import create_response_message
from .actor_view import ActorView
from .decorators import admin_only
from .decorators import standalone_only
from .decorators import token_required


class AdminView(MethodView):

    @standalone_only
    @token_required
    @cross_origin()
    def get(self):
        return redirect(url_for('auth_submodule.admin_profile'))

    @standalone_only
    @token_required
    @cross_origin()
    def post(self):
        session.pop('session_token', None)
        return redirect('/')


class AdminActorsView(MethodView):

    @standalone_only
    @admin_only
    @cross_origin()
    def get(self):
        actors = Actor.objects.filter()
        groups = Actor.objects.filter(actor_type='group')
        return render_template('admin_panel/actors.html', actors=actors, groups=groups)

    @standalone_only
    @admin_only
    @cross_origin()
    def post(self):
        if not request.is_json or not request.json.get('uinfo') or not request.json.get('actor_type'):
            response = create_response_message(message='Invalid request type', error=True)
            return make_response(jsonify(response), 400)
        actor = request.json
        response, status = ActorView.create_actor(actor)
        return make_response(jsonify(response), status)

    @standalone_only
    @admin_only
    @cross_origin()
    def delete(self):
        if not request.is_json or not request.json.get('uuid'):
            response = create_response_message(message='Invalid request type', error=True)
            return make_response(jsonify(response), 400)
        data = request.json
        response, status = ActorView.delete_actor(data.get('uuid'))
        return make_response(jsonify(response), status)


class AdminActorView(MethodView):

    @standalone_only
    @admin_only
    @cross_origin()
    def get(self, uuid):
        #TODO try catch for requests
        try:
            actor = Actor.objects.get(uuid=uuid)
        except ActorNotFound:
            raise NotFound('No actor with such UUID found')
        except errors.InvalidTextRepresentation:
            raise NotFound('Invalid UUID representation')

        uinfo = actor.uinfo

        if actor.actor_type in ['user', 'classic_user']:
            if actor.actor_type == 'classic_user':
                uinfo.pop('password')

        perms = actor.get_permissions()
        actor_groups = {group.uuid: group for group in actor.get_groups()}
        groups = Actor.objects.filter(actor_type='group')
        actors = Actor.objects.filter()
        return render_template('admin_panel/actor.html', actor=actor, perms=perms,
                               actor_groups=actor_groups, groups=groups, actors=actors)

    @standalone_only
    @admin_only
    @cross_origin()
    def put(self, uuid):
        if not request.is_json:
            response = create_response_message(message='Invalid request type', error=True)
            return make_response(jsonify(response), 400)

        data = request.json

        try:
            actor = Actor.objects.get(uuid=uuid)
        except ActorNotFound:
            response = create_response_message(message='No actor with such UUID found', error=True)
            return make_response(jsonify(response), 400)
        except errors.InvalidTextRepresentation:
            response = create_response_message(message='Invalid UUID representation', error=True)
            return make_response(jsonify(response), 400)

        if actor.actor_type in ['classic_user', 'user']:
            if data.get('password').strip():
                data['password'] = hash_md5(data.get('password'))
            else:
                data.pop('password')
            query = """UPDATE actor SET uinfo=uinfo || %s WHERE uuid=%s"""
            values = [json_dumps(data), uuid]

        elif actor.actor_type == 'group':
            users = data.get('users')
            if len(users) == 0:
                query = """UPDATE actor SET uinfo = jsonb_set(uinfo, '{groups}', (uinfo->'groups') - %s)
                           WHERE actor_type IN ('user', 'classic_user')"""
                values = [uuid]
            else:
                query = """UPDATE actor SET uinfo = jsonb_set(uinfo, '{groups}', uinfo->'groups' || %s) WHERE
                           actor_type IN ('user', 'classic_user') AND NOT uinfo->'groups' @> %s AND uuid IN %s;
                           UPDATE actor SET uinfo = jsonb_set(uinfo, '{groups}', (uinfo->'groups') - %s) WHERE 
                           actor_type IN ('user', 'classic_user') AND uuid NOT IN %s """
                values = [json_dumps(uuid), json_dumps(uuid), tuple(users), uuid, tuple(users)]

        try:
            with app.db.get_cursor() as cur:
                cur.execute(query, values)
        except Exception as e:
            print(f'Exception on updating actor! {e}')
            response = create_response_message(message='Some error occurred while actor updating.', error=True)
            return make_response(jsonify(response), 400)
        response = create_response_message(message='Actor successfully updated')
        return make_response(jsonify(response), 200)


class AdminProfileView(MethodView):

    @standalone_only
    @token_required
    @cross_origin()
    def get(self):
        return render_template('admin_panel/profile.html')

    @standalone_only
    @token_required
    @cross_origin()
    def put(self):
        if not request.is_json:
            response = create_response_message(message='Invalid request type', error=True)
            return make_response(jsonify(response), 400)

        data = request.json

        if not request.user:
            response = create_response_message(message='You are not authorized', error=True)
            return make_response(jsonify(response), 400)

        actor = request.user

        if data.get('password').strip():
            data['password'] = hash_md5(data.get('password'))
        else:
            data.pop('password')

        query = """UPDATE actor SET uinfo=uinfo || %s WHERE uuid=%s"""
        values = [json_dumps(data), actor.uuid]
        try:
            with app.db.get_cursor() as cur:
                cur.execute(query, values)
        except Exception as e:
            print(f'Exception on updating actor! {e}')
            response = create_response_message(message='Some error occurred while actor updating.', error=True)
            return make_response(jsonify(response), 400)
        response = create_response_message(message='Actor successfully updated')
        return make_response(jsonify(response), 200)


class AdminPermissionView(View):
    methods = ['POST', 'PUT', 'DELETE']

    @standalone_only
    @admin_only
    @cross_origin()
    def dispatch_request(self):
        if not request.is_json or not request.json.get('perms') or not request.json.get('actor_uuid'):
            response = create_response_message(message='Invalid request type', error=True)
            return make_response(jsonify(response), 400)
        data = request.json
        perms = data.get('perms')
        actor_uuid = data.get('actor_uuid')
        try:
            actor = Actor.objects.get(uuid=actor_uuid)
        except errors.InvalidTextRepresentation:
            response = create_response_message(message='Invalid actor uuid', error=True)
            return make_response(jsonify(response), 400)
        try:
            if request.method == 'POST':
                response, status = actor.set_permission(perms=perms)
            elif request.method == 'PUT':
                response, status = actor.update_permission(perms=perms)
            elif request.method == 'DELETE':
                response, status = actor.remove_permission(perms=perms)
        except errors.InvalidTextRepresentation:
            response = create_response_message(message='Invalid permission uuid', error=True)
            return make_response(jsonify(response), 400)
        return make_response(jsonify(response), status)
