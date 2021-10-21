"""
Permissions views for receiving information/changes from auth service and apply it on your service. All of methods are
could be used only if auth service sent this information.
"""
from flask import jsonify
from flask import make_response
from flask.views import MethodView
from flask import request
from flask import current_app as app
from flask_babel import gettext as _
from flask_cors import cross_origin

from .decorators import service_only
from .ecdsa_lib import verify_signature
from .service_view import SendCallback
from .utils import create_response_message
from .utils import json_dumps


class BasePermissionView:

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


class PermissionView(MethodView, BasePermissionView):
    f"""
    API endpoint for auth permissions management
    POST: /perms/
    """

    @service_only
    @cross_origin()
    def post(self):
        """
        Create permissions in database that was sent from auth
        :return:
        """
        data, error = self.verify_request_data()
        if error:
            return make_response(jsonify(data), 400)

        actor = data.get('actor')

        if not app.db.fetchone("""SELECT EXISTS(SELECT 1 FROM actor WHERE uuid = %s)""",
                               [actor.get('uuid')]).get('exists'):
            try:
                app.db.execute("""INSERT INTO actor SELECT * FROM jsonb_populate_record(null::actor, jsonb %s)""",
                               [json_dumps(actor)])
            except Exception as e:
                print('Error with creating actor. Exception - %s' % e)
                response = create_response_message(message=_("Some error occurred while creating actor."), error=True)
                return make_response(jsonify(response), 400)

        permission = data.get('permission')
        perm = app.db.fetchall("""SELECT * FROM insert_or_update_perms(%s)""", [json_dumps((permission))])
        if not perm:
            response = create_response_message(message=_("Some error occurred while creating permissions."), error=True)
            return make_response(jsonify(response), 400)

        SendCallback(action_type='create_permission', data=permission).send_callback()
        response = dict(
            message=_("Permission successfully updated.")
        )
        return make_response(jsonify(response), 200)

    @service_only
    @cross_origin()
    def delete(self):
        data, error = self.verify_request_data()
        if error:
            return make_response(jsonify(data), 400)

        data = data.get('permission')

        perm = app.db.fetchone("""DELETE FROM permissions WHERE actor_id=%s AND perm_id=%s RETURNING *""",
                               [data.get('actor_id'), data.get('perm_id')])

        if not perm:
            response = create_response_message(message=_("There is no permission such permission %(perm_id)s "
                                                         "in database", perm_id=data.get('perm_id')), error=True)
            return make_response(jsonify(response), 400)

        SendCallback(action_type='delete_permission', data=data).send_callback()
        response = dict(
            message=_("Permission successfully deleted.")
        )
        return make_response(jsonify(response), 200)
