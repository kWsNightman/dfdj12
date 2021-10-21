from flask import current_app as app
from flask import jsonify
from flask import make_response
from flask import request
from flask.views import MethodView
from flask_babel import gettext as _

from .decorators import service_only
from .utils import create_response_message

"""
Unused functionality for registration by custom link and automatically adding in some group
"""


class GetInviteLinkInfoView(MethodView):

    @service_only
    def post(self):
        if not request.is_json:
            response = create_response_message(message=_("Invalid request type."), error=True)
            return make_response(jsonify(response), 422)

        data = request.json

        if not data.get('link_uuid', None):
            response = create_response_message(message=_("Invalid request data."), error=True)
            return make_response(jsonify(response), 400)

        with app.db.get_cursor() as cur:
            cur.execute("SELECT * FROM invite_link WHERE uuid = %s", (data.get('link_uuid'),))
            identifier = cur.fetchone()

        response = dict(
            identifier=identifier
        )
        return make_response(jsonify(response), 200)
