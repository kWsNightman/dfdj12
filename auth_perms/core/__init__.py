from flask import Blueprint
from flask import request
from flask_socketio import SocketIO

from .actor import Actor
from .decorators import data_parsing
from .exceptions import AuthPermsDataError
from .managers import DatabaseManager
from .utils import delete_salt

# Base auth_perms blueprint
auth_submodule = Blueprint(name="auth_submodule", import_name=__name__, template_folder='templates',
                           static_url_path='/auth_perms/core/static', static_folder='static')

# Main socket object
socketio = SocketIO(cors_allowed_origins='*', async_handlers=True)

# Urls on apps in google market and appstore
ERP_APP_URL = dict(
    android='https://play.google.com/store/apps/details?id=ecosystem54.android',
    ios='https://apps.apple.com/us/app/ecosystem54/id1496286184'
)


@auth_submodule.after_request
@data_parsing
def after_request(response, **kwargs):
    # Delete salt that was used
    if request.method == 'POST' and request.path == '/auth/' and response.status_code == 200:
        data = kwargs.get('data')
        if 'signed_salt' in data:
            if 'uuid' in data:
                salt = delete_salt({'uuid': data.get('uuid')})
            elif 'qr_token' in data:
                salt = delete_salt({'qr_token': data.get('qr_token')})
            elif 'apt54' in data:
                #salt = delete_salt({'uuid': data['apt54']['user_data'].get('uuid')})
                salt = None
                pass
                if not salt:
                    pass
                    #salt = delete_salt({'pub_key': data['apt54']['user_data'].get('initial_key')})
            else:
                # TODO: This print need to check event that do not exists here.
                salt = None

            if not salt:
                print('ERROR with deleting salt. Everything ok. data - %s' % data)

    return response


# Import auth perms socket events
from . import socket_events
