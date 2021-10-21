import base64
import json
import requests
import qrcode
from io import BytesIO
from urllib.parse import urljoin

from flask import jsonify
from flask import make_response
from flask import current_app as app
from flask import render_template
from flask import request
from flask import session
from flask import url_for
from flask.views import MethodView
from flask_babel import gettext as _
from flask_cors import cross_origin
from flask_socketio import emit

from . import auth_submodule
from . import ERP_APP_URL
from .actor import ActorNotFound
from .decorators import data_parsing
from .decorators import service_only
from .ecdsa_lib import sign_data
from .ecdsa_lib import verify_signature
from .exceptions import Auth54ValidationError
from .utils import set_actor_sid
from .utils import create_new_salt
from .utils import get_apt54
from .utils import get_default_user_group
from .utils import get_public_key
from .utils import get_user_sid
from .utils import hash_md5
from .utils import json_dumps
from .utils import get_user_salt
from .utils import check_if_auth_service
from .utils import verify_apt54
from .utils import apt54_expired
from .utils import create_session
from .utils import create_temporary_session
from .utils import actor_exists
from .utils import create_actor
from .utils import update_user
from .utils import create_response_message
from .utils import generate_qr_token
from .utils import get_static_group
from .utils import validate_email
from .utils import update_salt_data
from .utils import get_auth_domain
from .utils import print_error_cli
from .utils import get_language_header
from .utils import get_service_locale
from .utils import get_session_token_by_auxiliary
from .utils import delete_temporary_session
from .utils import get_apt54_locally
from .static_builder import StaticBuilder


class AboutView(MethodView):
    @cross_origin()
    def get(self):
        query = """SELECT uuid AS uuid, uinfo->>'service_name' AS service_name, 
        uinfo->>'service_domain' AS service_domain FROM actor WHERE uuid = %s AND actor_type = 'service'"""
        service_info = app.db.fetchone(query, [app.config['SERVICE_UUID']])

        if not service_info:
            print_error_cli(message="There is not service info. core.auth_view.AboutView - GET.")
            response = create_response_message(message=_("Some error occurred while getting service info."), error=True)
            return make_response(jsonify(response), 400)

        query = """SELECT uuid AS uuid, uinfo->>'biom_name' AS biom_name, uinfo->>'service_domain' AS service_domain 
        FROM actor WHERE actor_type='service' AND initial_key=%s"""
        if app.config.get('AUTH_STANDALONE'):
            auth_info = app.db.fetchone(query, [app.config.get('SERVICE_PUBLIC_KEY')])
        else:
            auth_info = app.db.fetchone(query, [app.config.get('AUTH_PUB_KEY')])
        if not auth_info:
            print_error_cli(message="There is not biom info. core.auth_view.AboutView - GET.")
            response = create_response_message(message=_("Some error occurred while getting service info."), error=True)
            return make_response(jsonify(response), 400)

        response = dict(
            biom_uuid=auth_info.get('uuid'),
            biom_name=auth_info.get('biom_name', 'Unknown'),
            biom_domain=auth_info.get('service_domain', 'Unknown'),
            service_uuid=service_info.get('uuid', 'Unknown'),
            service_name=service_info.get('service_name', 'Unknown'),
            service_domain=service_info.get('service_domain', 'Unknown'),
        )

        return make_response(jsonify(response), 200)


class AuthSSOView(MethodView):
    
    @cross_origin()
    def get(self):
        temporary_session = create_temporary_session()
        redirect_url = request.args.get('redirect_url')
        if redirect_url not in ['admin/auth/sign-in', 'admin/auth/sign-up',
                                '/admin/auth/sign-in', '/admin/auth/sign-up']:
            redirect_url = ''

        domain = urljoin(get_auth_domain(), '/auth_sso/')

        data = dict(
            domain=domain,
            session=temporary_session,
            uuid=app.config['SERVICE_UUID'],
            service=app.config.get("SERVICE_NAME", "").lower()
        )
        return make_response(jsonify(data), 200)

    @service_only
    @cross_origin()
    def post(self):
        data = request.json
        signature = data.pop('signature')
        if not data or not signature:
            print_error_cli(message="Error with data. core.auth_view.AuthSSOView - POST.\n "
                                    "data - %s, signature - %s" % (data, signature))
            response = create_response_message(message=_("Invalid request data."), error=True)
            return make_response(jsonify(response), 422)

        if not verify_signature(app.config['AUTH_PUB_KEY'], signature, json_dumps(data, sort_keys=True)):
            print_error_cli(message="Signature verification. core.auth_view.AuthSSOView - POST.\n "
                                    "data - %s, signature - %s" % (data, signature))
            response = create_response_message(message=_("Signature verification failed."), error=True)
            return make_response(jsonify(response), 400)

        apt54 = data.get('apt54')
        if not apt54:
            print_error_cli(message="There is no APT54 token. core.auth_view.AuthSSOView - POST.\n data - %s" % data)
            response = create_response_message(message=_("There is no authentication token. "
                                                         "Please try again or contact the administrator."), error=True)
            return make_response(jsonify(response), 400)

        uuid = apt54['user_data'].get('uuid', None)
        if not uuid:
            print_error_cli(message="There is not uuid in APT54. core.auth_view.AuthSSOView - POST\n "
                                    "apt54 - %s" % apt54)
            response = create_response_message(message=_("Invalid data in your authentication token. "
                                                         "Please try again or contact the administrator."), error=True)
            return make_response(jsonify(response), 400)

        if not actor_exists(uuid):
            # Add actor info in user_data key, cause create_actor function, creates user by apt54.
            actor = dict(
                user_data=data.get('actor')
            )
            if not create_actor(actor):
                # Error while creating user
                print_error_cli(message="Error with creating actor. core.auth_view.AuthSSOView - POST.\n "
                                        "actor - %s" % actor)
                response = create_response_message(message=_("Some error occurred while creating actor. "
                                                             "Please try again or contact the administrator."),
                                                   error=True)
                return make_response(jsonify(response), 400)

        response = create_session(apt54, auxiliary_token=data.get('temporary_session'))
        if isinstance(response, dict) and response.get('error'):
            return make_response(jsonify(response), 401)

        session_token = response
        if not session_token:
            print_error_cli(message="Error with creating session token. core.auth_view.AuthSSOView - POST.\n "
                                    "error - %s" % response)
            response = create_response_message(message=_("Some error occurred while creating session token. "
                                                         "Please try again or contact the administrator."), error=True)
            return make_response(jsonify(response), 400)

        response = create_response_message(message=_("Session token was successfully created."))
        return make_response(jsonify(response), 200)


class QRCodeView(MethodView):
    """
    :flow: 01 "QR code generation."
    :flow: 01-01(|Scanning|02-01) "Parameters: </br> - qr_token </br> - salt </br> - domain </br> - biom_uuid </br>"
    """

    @cross_origin()
    def get(self, **kwargs):
        if request.args.get('qr_type', None) == 'application':
            img_io = self.generate_qr_image(ERP_APP_URL)
            response = dict(
                qr_code=base64.b64encode(img_io.getvalue()).decode(),
            )
            return make_response(jsonify(response), 200)

        query = """SELECT uinfo->>'service_domain' AS service_domain FROM actor WHERE uuid = %s"""
        service_domain = app.db.fetchone(query, [app.config.get('SERVICE_UUID')])
        if not service_domain:
            raise ActorNotFound

        data = kwargs.get('data', {})

        registration_url = data.get('registration_url') if data.get('registration_url') else \
            urljoin(service_domain.get('service_domain'), url_for('auth_submodule.reg'))
        apt54_url = urljoin(service_domain.get('service_domain'), url_for('auth_submodule.apt54'))
        authentication_url = data.get('authentication_url') if data.get('authentication_url') else \
            urljoin(service_domain.get('service_domain'), url_for('auth_submodule.auth'))
        about_url = data.get('about_url') if data.get('about_url') else \
            urljoin(service_domain.get('service_domain'), url_for('auth_submodule.about'))

        qr_type = None

        if request.args.get('qr_type'):
            if request.args.get('qr_type') not in ['registration', 'authentication']:
                print_error_cli(message="Error with getting qr_type from request args. core.auth_view.QRCodeView - "
                                        "GET.\n request.args - %s" % request.args)
                response = create_response_message(message=_("Unknown QR type. "
                                                             "Please try again or contact the administrator."),
                                                   error=True)
                return make_response(jsonify(response), 400)

            qr_type = request.args.get('qr_type')

        if data.get('qr_type') and not qr_type:
            if data.get('qr_type') not in ['registration', 'authentication']:
                print_error_cli(message="Error with getting qr_type from kwargs. core.auth_view.QRCodeView - "
                                        "GET.\n kwargs - %s" % kwargs)
                response = create_response_message(message=_("Unknown QR type. "
                                                             "Please try again or contact the administrator."),
                                                   error=True)
                return make_response(jsonify(response), 400)

            qr_type = data.get('qr_type')

        if not qr_type:
            print_error_cli(message="Error with getting qr_type from request args and kwargs. "
                                    "core.auth_view.QRCodeView - GET.\n")
            response = create_response_message(message=_("There is no QR type. "
                                                         "Please try again or contact the administrator."), error=True)
            return make_response(jsonify(response), 400)

        qr_token = generate_qr_token()
        salt = create_new_salt(user_info={'qr_token': qr_token}, salt_for=qr_type)
        if not salt:
            print_error_cli(message="Error with creating salt. core.auth_view.QRCodeView - GET.\n salt - %s" % salt)
            response = create_response_message(message=_("Some error occurred while creating verification data. "
                                                         "Please try again or contact the administrator."),
                                               error=True)
            return make_response(jsonify(response), 400)

        if qr_type == 'registration':
            data = dict(
                qr_token=qr_token,
                salt=salt,
                about_url=about_url,
                registration_url=registration_url,
                apt54_url=apt54_url,
                authentication_url=authentication_url
            )
            #img_io = self.generate_qr_image(data)
            #response = dict(
            #    qr_code=base64.b64encode(img_io.getvalue()).decode(),
            #    qr_token=qr_token
            #)
            response = data
        else:
            response = dict(
                qr_token=qr_token,
                salt=salt,
                about_url=about_url,
                apt54_url=apt54_url,
                authentication_url=authentication_url
            )
            response.update(
                {"depended_services": self.get_depended_qr_info()}
            )
        return make_response(jsonify(response), 200)

    def get_depended_qr_info(self):
        services_info = dict()
        for name, domain in app.config.get("DEPENDED_SERVICES", {}).items():
            if not domain.endswith("/"):
                domain += "/"
            try:
                services_info.update({
                    name: dict(
                        requests.get(
                            domain + "get_qr_code/",
                            params={"qr_type": "authentication"}
                        ).json()
                    )}
                )
            except Exception:
                continue
        return services_info

    @staticmethod
    def generate_qr_image(data):
        qr = qrcode.QRCode(
            version=1,
            error_correction=qrcode.constants.ERROR_CORRECT_L,
            box_size=10,
            border=4
        )
        qr.add_data(data)
        qr.make(fit=True)

        img = qr.make_image()
        img_io = BytesIO()
        img.save(img_io, 'PNG')
        img_io.seek(0)
        return img_io


class BaseAuth(MethodView):

    @staticmethod
    def check_if_from_client_service(data):
        """
        Check if request was sent from client service. If request came from client service - verify signature
        :param data: request data
        :return: dict with flag from_service: True/False. If verification error also error True and error_message.
        """
        response = dict(
            from_service=False
        )
        if 'service_uuid' in data:
            query = "SELECT initial_key FROM actor WHERE uuid = %s AND actor_type = 'service'"
            values = [data.get('service_uuid')]
            service_info = app.db.fetchone(query, values)

            if not service_info:
                print_error_cli(message="Unknown service. core.auth_view.BaseAuth - check_if_from_client_service.\n "
                                        "data - %s, service_info - %s" % (data, service_info))
                response = create_response_message(message=_("Unknown service."), error=True)
                response['from_service'] = True
                return response

            service_pub_key = service_info.get('initial_key')
            signature = data.pop('signature')
            if not verify_signature(service_pub_key, signature, json_dumps(data, sort_keys=True)):
                print_error_cli(message="Signature verification error. core.auth_view.BaseAuth - "
                                        "check_if_from_client_service.\n data - %s, signature - %s" % (data, signature))
                response = create_response_message(message=_("Signature verification failed."), error=True)
                response['from_service'] = True
                return response

            response['from_service'] = True

        return response

    @staticmethod
    def add_default_group(data):
        """
        Validate default group received from client service or adding auth default group.
        :param data: request data
        :return: uinfo or dict with error True and error_message.
        """
        uinfo = data.get('uinfo', {})
        if uinfo.get('groups', None):
            groups = uinfo.get('groups')
            query = "SELECT uuid FROM actor WHERE uuid = ANY(%s::uuid[])"
            values = [groups]
            groups_uuid = app.db.fetchall(query, values)

            if len(groups_uuid) != len(groups):
                invalid_groups = [group for group in groups if group not in groups_uuid]
                print_error_cli(message="Unknown group. core.auth_view.BaseAuth - add_default_group.\n "
                                        "invalid_groups - %s" % invalid_groups)
                response = create_response_message(message=_("There is no such groups %(invalid_groups)s",
                                                             invalid_groups=invalid_groups), error=True)
                return response

            if groups_uuid:
                # TODO: change from admin on alowed groups when frontend add this flag
                admin_group = get_static_group('ADMIN')
                if not admin_group:
                    print_error_cli(message="There is no admin group. core.auth_view.BaseAuth - add_default_group.\n")
                    response = create_response_message(message=_("Some error occurred with admin group."), error=True)
                    return response

                if admin_group.get('uuid') in groups:
                    print_error_cli(message="Default group is admin. core.auth_view.BaseAuth - add_default_group.\n "
                                            "data - %s" % data)
                    response = create_response_message(message=_("This group can't be used by default "
                                                                 "for your service."), error=True)
                    return response

        else:
            default_group = get_default_user_group()
            if default_group:
                uinfo['groups'] = [default_group.get('uuid')]
            else:
                uinfo['groups'] = []

        return uinfo

    @staticmethod
    def upgrade_salt_for(salt, actor_uuid, qr_token, salt_for='authentication'):
        app.db.execute("""UPDATE salt_temp SET salt_for = %s WHERE salt = %s AND uuid = %s AND qr_token = %s""",
                       [salt_for, salt, actor_uuid, qr_token])


class RegistrationView(BaseAuth):
    """
    Registration with auth service
    :group: (01,02,03,04,05) "01. Registration process"
    :flow: 02 "Registration"
    :flow: 02-01?(|true|02-02,|false|02-03) "User is local"
    """

    # TODO: Add cross_origin, but cause of resending on auth it raise exception with double Allow Origin.
    @data_parsing
    def post(self, **kwargs):
        data = kwargs.get('data')
        sid = get_user_sid(data.get('qr_token'))
        # :flow: 02-03?(|true|02-04,|false|03-01) "Is auth service"
        if not check_if_auth_service():
            if not app.config.get('AUTH_STANDALONE'):
                # :flow: 03 "Client service registration"
                # :flow: 03-01(03-02) "Adding service default group in user info"
                # :flow: 03-02(03-03) "Adding: </br> - salt </br> - service uuid </br> in request data and signing data with service private key"
                data = self.collect_data_for_auth(data, salt_for='registration')
                # :flow: 03-03(|POST|04-01) "Send request on auth service registration endpoint"
                response = requests.post(urljoin(get_auth_domain(), '/reg/'), json=data,
                                         headers=get_language_header())
                # :flow: 03-04(03-05) "Response from auth"
                if response.ok:
                    response_data = response.json()
                    user = response_data.pop('user')
                    # :flow: 03-05(03-06) "Create user on client service with data from auth service"
                    try:
                        query = "INSERT INTO actor SELECT * FROM jsonb_populate_record(null::actor, jsonb %s)"
                        values = [json_dumps(user)]
                        app.db.execute(query, values)
                    except Exception as e:
                        print('Exception on creating user! %s' % e)
                        print_error_cli(message="Error on creating user. core.auth_view.RegistrationView - POST.\n "
                                                "user - %s" % user)
                        response = create_response_message(message=_("Some error occurred while actor registration. "
                                                                     "Please contact the administrator."), error=True)

                        emit('auth status', response, room=sid, namespace='/')
                        return make_response(jsonify(response), 400)

                    if data.get('actor_type') == 'classic_user':
                        response = create_response_message(message=_("You are successfully registered."))
                        return make_response(jsonify(response), 200)

                    content = json.loads(response.text)
                    content['user_uuid'] = user.get('uuid')
                    content.pop('user')
                    text = json_dumps(content)

                    # Upgrade salt for using the same one in authentication
                    salt = update_salt_data(user.get('uuid'), data.get('qr_token'))
                    self.upgrade_salt_for(salt=salt.get('salt'), actor_uuid=salt.get('uuid'),
                                          qr_token=data.get('qr_token'), salt_for='authentication')
                else:
                    text = response.text

                if response.status_code == 200 and sid:
                    service_response = dict(
                        message=_("You are successfully registered.")
                    )
                    emit('auth status', service_response, room=sid, namespace='/')
                elif sid:
                    try:
                        service_response = json.loads(text)
                    except Exception as e:
                        print_error_cli(message="Error with converting response in json in registration. error - %s" % e)
                        service_response = create_response_message(message=_("Auth service is unreachable. Please try "
                                                                             "again or contact the administrator"),
                                                                   error=True)

                    emit('auth status', service_response, room=sid, namespace='/')

                if data.get('actor_type') == 'classic_user':
                    return make_response(jsonify(json.loads(text)), response.status_code)

                # :flow: 03-06 "Response to core ERP app"
                return text, response.status_code, response.headers.items()

        if data.get('actor_type') == 'classic_user':
            response, status = self.registration_classic_user(data)
            return make_response(jsonify(response), status)

        # :flow: 02-04(04-01) "Registration user on auth service"
        response, status = self.registration(data)

        if status == 200:
            salt = update_salt_data(response.get('user_uuid'), data.get('qr_token'))
            # Update salt from registration to authentication for next step.
            if salt:
                self.upgrade_salt_for(salt=salt.get('salt'), actor_uuid=salt.get('uuid'),
                                      qr_token=data.get('qr_token'), salt_for='authentication')
            else:
                print('Error with salt updating')

        if status == 200 and sid:
            service_response = dict(
                message=_("You are successfully registered.")
            )
            emit('auth status', service_response, room=sid, namespace='/')
        elif sid:
            emit('auth status', response, room=sid, namespace='/')

        return make_response(jsonify(response), status)

    def registration(self, data: dict):
        """
        Registration step two. In this step we check signed salt and if everything is good create user and return uuid
        :param data: dictionary with uuid and signed salt
        :return: response, status: response - dictionary with uuid of error=True flag with error message, status -
        http code
        :flow: 04 "Registration on auth service"
        :flow: 04-01(04-02) " Auth service registration "
        :flow: 04-02(04-03) "Validate received data"
        """
        signed_salt = data.get('signed_salt')
        pub_key = data.get('pub_key')
        qr_token = data.get('qr_token')
        if not pub_key or not signed_salt or not qr_token:
            # There is no public key or signed salt. Not full data set
            print_error_cli(message="Wrong data was sent. core.auth_view.RegistrationView - registration.\n "
                                    "pub_key - %s, signed_salt - %s, qr_token - %s" % (isinstance(pub_key, str),
                                                                                       isinstance(signed_salt, str),
                                                                                       isinstance(qr_token, str)))
            response = create_response_message(message=_("Invalid request data."), error=True)
            return response, 400

        # Check if request was sent from client service.
        result = self.check_if_from_client_service(data)
        if result.get('from_service'):
            if result.get('error'):
                result.pop('from_service')
                return result, 400

            salt = data.get('salt')
        else:
            salt = get_user_salt({'qr_token': qr_token}, salt_for='registration')

        if not salt:
            # There is no salt generated for that public key
            print_error_cli(message="There is no salt. core.auth_view.RegistrationView - registration.\n "
                                    "qr_token - %s, salt - %s" % (qr_token, salt))
            response = create_response_message(message=_("There is no verification data based on received data. \n "
                                                         "Please get new QR code."),
                                               error=True)
            return response, 400

        # :flow: 04-03(04-04) "Verify salt signature"
        if not verify_signature(pub_key, signed_salt, salt):
            # Wrong signature verification
            print_error_cli(message="Signature verification failed. core.auth_view.RegistrationView - registration.\n")
            response = create_response_message(message=_("Signature verification failed."), error=True)
            return response, 400

        # :flow: 04-04(04-05) "Add service default group in user info"
        uinfo = self.add_default_group(data)
        if uinfo.get('error'):
            # Error with adding default group
            return uinfo, 400

        if uinfo.get('email', None):
            if app.db.fetchone("""SELECT EXISTS(SELECT 1 FROM actor WHERE uinfo ->> 'email' = %s)""",
                               [uinfo.get('email')]).get('exists'):
                print_error_cli(message="User with such email already exists. core.auth_view. "
                                        "RegistrationView - registration.\n email - %s" % uinfo.get('email'))
                response = create_response_message(message=_("Actor with such email already exists."), error=True)
                return response, 400

            try:
                validate_email(uinfo.get('email'))
            except Auth54ValidationError as e:
                print_error_cli(message="Invalid email was inputed. core.auth_view. "
                                        "RegistrationView - registration.\n email - %s" % uinfo.get('email'))
                response = create_response_message(message=_("Email you have inputted is invalid. Please check it."),
                                                   error=True)
                return response, 400
        else:
            print_error_cli(message="User with has not input email. core.auth_view. "
                                    "RegistrationView - registration.\n uinfo - %s" % uinfo)
            response = create_response_message(message=_("There is no email in received data."), error=True)
            return response, 400

        # :flow: 04-05(04-06) "Getting auth info for core ERP app"
        # :flow: 04-06(04-07) "Creating user"
        try:
            user = app.db.fetchone("""INSERT INTO actor(initial_key, uinfo) VALUES (%s, %s::jsonb) RETURNING *""",
                                   [pub_key, json_dumps(uinfo)])
        except Exception as e:
            print('Exception on creating user! RegistrationView - registration. \n Exception - %s' % e)
            user = None

        if not user:
            # actor trigger returned None if such public_key already exists
            print_error_cli(message="Error with creating user. core.auth_view.RegistrationView - registration.\n "
                                    "pub_key - %s, uinfo - %s" % (pub_key, uinfo))
            response = create_response_message(message=_("Some error occurred while creating actor. "
                                                         "Please try again or contact the administrator"), error=True)
            return response, 400

        # :flow: 04-07?(|true|04-08,|false|03-04) "If auth service"
        # :flow: 04-08 "Response to core ERP app"
        if result.get('from_service'):
            response = dict(
                user=user
            )
        else:
            response = dict(
                user_uuid=user.get('uuid')
            )

        return response, 200

    def registration_classic_user(self, data: dict):
        """
        Classic registration with login/password.
        :param data: login, password, password_confirmation
        :return: response, status: response - dictionary with created user or error=True flag with error message,
        status - http code
        """
        if not data.get('email') or not data.get('password') or not data.get('password_confirmation'):
            print_error_cli(message="Wrong data. core.auth_view.RegistrationView - registration_classic_user.\n "
                                    "email - %s, password - %s, "
                                    "password_confirmation - %s" % (data.get('email'),
                                                                    isinstance(data.get('password'), str),
                                                                    isinstance(data.get('password_confirmation'), str)))
            response = create_response_message(message=_("Invalid request data."), error=True)
            return response, 400

        result = self.check_if_from_client_service(data)
        if result.get('from_service'):
            if result.get('error'):
                result.pop('from_service')
                return result, 400

        groups = None
        email = data.get('email')
        password = data.get('password')
        password_confirmation = data.get('password_confirmation')
        if password != password_confirmation:
            print_error_cli(message="Password and password confirmation do not match. "
                                    "core.auth_view.RegistrationView - registration_classic_user. ")
            response = create_response_message(message=_("Password and password confirmation do not match. "
                                                         "Please check it."), error=True)
            return response, 400

        try:
            validate_email(email)
        except Auth54ValidationError as e:
            response = create_response_message(message=_("Email you have inputted is invalid. Please check it."),
                                               error=True)
            return response, 400

        if app.db.fetchone("SELECT EXISTS(SELECT 1 FROM actor WHERE uinfo->>'email' = %s "
                           "AND actor_type = ANY(ARRAY['classic_user', 'user']))", [email]).get('exists'):
            print_error_cli(message="User with such email exists. "
                                    "core.auth_view.RegistrationView - registration_classic_user.\n email - %s" % email)
            response = create_response_message(message=_("Actor with such email already exists."), error=True)
            return response, 400

        uinfo = data.get('uinfo')
        if uinfo:
            if not isinstance(uinfo, dict):
                print_error_cli(message="Uinfo is not a dict. "
                                        "core.auth_view.RegistrationView - registration_classic_user.\n"
                                        "uinfo type - %s" % type(uinfo))
                response = create_response_message(message=_("Invalid request data type."), error=True)
                return response, 400
            if 'email' in uinfo:
                print_error_cli(message="Email is in uinfo.core.auth_view.RegistrationView - registration_classic_user")
                response = create_response_message(
                    message=_("Invalid parameter email in optional data."),
                    error=True
                )
                return response, 400
            if 'password' in uinfo:
                print_error_cli(message="Password is in uinfo. "
                                        "core.auth_view.RegistrationView - registration_classic_user")
                response = create_response_message(
                    message=_("Invalid parameter password in optional data."),
                    error=True
                )
                return response, 400

        password = hash_md5(password)
        if data.get('identifier', None):
            invite_link_info= app.db.fetchone("""SELECT service_uuid, link_uuid FROM invite_link_temp 
            WHERE params->>'identifier' = %s""", [data.get('identifier')])

            if invite_link_info:
                service_info = app.db.fetchone("""SELECT uinfo->>'service_domain' AS service_domain, 
                initial_key AS initial_key FROM actor WHERE uuid=%s AND actor_type='service'""",
                                               [invite_link_info.get('service_uuid')])

                if service_info:
                    service_domain = service_info.get('service_domain')
                    request_data = dict(
                        service_uuid=app.config['SERVICE_UUID'],
                        link_uuid=invite_link_info.get('link_uuid')
                    )
                    request_data['signature'] = sign_data(app.config['SERVICE_PRIVATE_KEY'],
                                                          json_dumps(request_data, sort_keys=True))
                    response = requests.post(urljoin(service_domain, '/get_invite_link_info/'), json=request_data,
                                             headers=get_language_header())
                    if response.ok:
                        response_data = json.loads(response.content)
                        link = response_data.get('link')
                        admin_group = get_static_group('ADMIN')
                        if not isinstance(admin_group, dict) and admin_group.get('uuid') != link.get('group_uuid'):
                            groups = [link.get('group_uuid')]

        uinfo = self.add_default_group(data)

        if uinfo.get('error'):
            # Error with adding default group
            return uinfo, 400

        if groups:
            uinfo['groups'] += groups

        uinfo.update(dict(
            email=email,
            password=password))

        query = "INSERT INTO actor(uinfo, actor_type) VALUES (%s::jsonb, %s) RETURNING *"
        values = [json_dumps(uinfo), 'classic_user']
        try:
            user = app.db.fetchone(query, values)
        except Exception as e:
            print('Exception on creating user! %s' % e)
            pwd = uinfo.pop('password')
            pwd_confirmation = uinfo.pop('password_confirmation')
            print_error_cli(message="Error with creating user "
                                    "core.auth_view.RegistrationView - registration_classic_user.\n "
                                    "uinfo - %s, password not exists - %s, "
                                    "password_confirmation not exists - %s" % (uinfo, not pwd, not pwd_confirmation))
            response = create_response_message(message=_("Some error occurred while creating actor. "
                                                         "Please try again."), error=True)
            return response, 400

        response = dict(
            user=user
        )
        return response, 200

    @staticmethod
    def collect_data_for_auth(data, salt_for: str = None):
        uinfo = data.get('uinfo', {})
        default_group = get_default_user_group()
        if default_group:
            if uinfo.get('groups'):
                if isinstance(uinfo.get('groups'), list):
                    uinfo['groups'].append(default_group.get('uuid'))
                else:
                    uinfo['groups'] = [default_group.get('uuid')]
            else:
                uinfo['groups'] = [default_group.get('uuid')]
        else:
            if not uinfo.get('groups') or not isinstance(uinfo.get('groups'), list):
                uinfo['groups'] = []

        data['uinfo'] = uinfo
        if data.get('actor_type', None) != 'classic_user':
            data['salt'] = get_user_salt({'qr_token': data.get('qr_token')}, salt_for=salt_for)

        data['service_uuid'] = app.config['SERVICE_UUID']
        data['signature'] = sign_data(app.config['SERVICE_PRIVATE_KEY'], json_dumps(data, sort_keys=True))
        return data


class APT54View(MethodView):
    """
    Authentication with getting apt54
    :group: (06) "02. Authentication process"
    """
    @cross_origin()
    @data_parsing
    def post(self, **kwargs):
        data = kwargs.get("data")
        if data.get('step', None) and data.get('step', None) == 1 and data.get('uuid'):
            salt = create_new_salt({"uuid": data.get('uuid')}, salt_for='authentication')

            if not salt:
                print_error_cli(message="Error with creating salt. core.auth_view.APT54View - POST.\n "
                                        "salt - %s, uuid - %s" % (salt, data.get('uuid')))
                response = create_response_message(message=_("Some error occurred while creating verification data. "
                                                             "Please try again or contact the administrator."),
                                                   error=True)
                return make_response(jsonify(response), 400)

            response = dict(
                salt=salt
            )
            return make_response(jsonify(response), 200)

        # :flow: 06 "Authentication"
        # :flow: 06-01(06-02) "Start authentication"
        response, status = self.authentication(data)

        sid = get_user_sid(data.get('qr_token'))
        if status == 200:
            salt = update_salt_data(data.get('uuid'), data.get('qr_token'))
            if not salt:
                print('Error with salt updating')

        if status == 200 and sid:
            service_response = dict(
                message=_("You are successfully receive your authentication token.")
            )
            emit('auth status', service_response, room=sid, namespace='/')
        elif sid:
            emit('auth status', response, room=sid, namespace='/')
        # :flow: 06-11 "Response to core ERP app"
        return make_response(jsonify(response), status)

    def authentication(self, data: dict):
        """
        Authentication step two. In this step check signed salt and if everything is good ask in auth apt54 and return
        it to user
        :param data: dictionary with uuid and signed salt
        :return: response, status: response - dictionary with apt54 of error=True flag with error message, status - http
        code
        :flow: 06-02(06-03) "Validate received data"
        """
        signed_salt = data.get('signed_salt', None)
        uuid = data.get('uuid', None)
        qr_token = data.get('qr_token', None)
        step = data.get('step', None)

        if not uuid or not signed_salt or (not step == 2 and not qr_token):
            # There is no uuid or signed salt. Not full data set
            print_error_cli(message="Wrong data was sent. core.auth_view.APT54View - authentication.\n "
                                    "uuid - %s, signed_salt not exists - %s, "
                                    "step - %s, qr_token - %s" % (uuid, not signed_salt, step, qr_token))
            response = create_response_message(message=_("Invalid request data."), error=True)
            return response, 400

        if step:
            salt = get_user_salt({"uuid": uuid}, salt_for='authentication')
        else:
            salt = get_user_salt({'qr_token': qr_token, 'uuid': uuid}, salt_for='authentication')

        if not salt:
            # There is no salt generated for that public key
            print_error_cli(message="Wrong with getting salt. core.auth_view.APT54View - authentication.\n "
                                    "salt - %s, uuid - %s, qr_token - %s" % (salt, uuid, qr_token))
            response = create_response_message(message=_("There is no verification data based on received data. \n "
                                                         "Please get new QR code. "),
                                               error=True)
            return response, 400

        # :flow: 06-03(06-04) "Getting user public key </br> and keys if they were regenerated"
        initial_key, secondary_keys = get_public_key(uuid)
        if not initial_key and not secondary_keys:
            # User has no public key
            print_error_cli(message="User has no public key. core.auth_view.APT54View - authentication.\n "
                                    "uuid - %s, initial_key - %s, "
                                    "secondary_keys - %s" % (uuid, initial_key, secondary_keys))
            response = create_response_message(message=_("There is no your public key for your actor. "
                                                         "Please contact the administrator."), error=True)
            return response, 400

        # :flow: 06-04?(|true|06-05,|false|06-06) "Verify salt signature with primary public key"
        if verify_signature(initial_key, signed_salt, salt):
            # Signature verification passed with initial key
            # :flow: 06-05(06-11) "Getting apt54 from auth service"
            return self.get_apt54_with_response(uuid)

        else:

            # :flow: 06-06?(|true|06-07,|false|06-08) "Service use only primary key"
            if app.config.get('PRIMARY_KEY_ONLY'):
                # :flow: 06-07 "Error response"
                # Important service uses only primary initial key
                print_error_cli(message="Signature verification error Because PRIMARY_KEY_ONLY is True and "
                                        "verification by initial_key failed. "
                                        "core.auth_view.APT54View - authentication.\n ")
                response = create_response_message(message=_("Signature verification failed."), error=True)
                return response, 400

            if secondary_keys:
                for public_key in secondary_keys:
                    # :flow: 06-08?(|true|06-09,|false|06-10) "Verify signature with secondary keys"
                    # Check signature with secondary generated keys
                    if verify_signature(public_key, signed_salt, salt):
                        # :flow: 06-09(06-11) "Getting apt54 from auth service"
                        return self.get_apt54_with_response(uuid)

        # :flow: 06-10 "Error message"
        print_error_cli(message="Signature verification error. core.auth_view.APT54View - authentication.\n ")
        response = create_response_message(message=_("Signature verification failed."), error=True)
        return response, 400

    @staticmethod
    def get_apt54_with_response(uuid: str):
        if app.config.get('AUTH_STANDALONE'):
            apt54, status_code = get_apt54_locally(uuid)
        else:
            apt54, status_code = get_apt54(uuid)
        if status_code == 452:
            print_error_cli(message="Error with getting apt54. There is no such user with uuid - %s. "
                                    "core.auth_view.APT54View - get_apt54_with_response.\n" % uuid)
            response = create_response_message(message=_("There is no such actor. Please contact the administrator"),
                                               error=True)
            status = 400
        elif not apt54:
            print_error_cli(message="Error with getting apt54. core.auth_view.APT54View - get_apt54_with_response.\n "
                                    "uuid - %s" % uuid)
            response = create_response_message(message=_("Auth service is unreachable. "
                                                         "Please try again or contact the administrator."), error=True)
            status = 400
        elif status_code == 200:
            status = 200
            response = dict(
                apt54=json_dumps(apt54)
            )
        else:
            print_error_cli(message="Error with getting apt54. core.auth_view.APT54View - get_apt54_with_response.\n "
                                    "uuid - %s" % uuid)
            response = create_response_message(message=_("Some error occurred with getting your authentication token. "
                                                         "Please try again or contact the administrator."), error=True)
            status = 400
        return response, status


class ClientAuthView(BaseAuth):
    """
    Authorization on client service
    :group: (07,08) "03. Authorization process"
    :flow: 07 "Authorization"
    :flow: 07-01?(|true|07-02,|false|07-03) "User is local"
    """
    @cross_origin()
    @data_parsing
    def post(self, **kwargs):
        data = kwargs.get("data")
        if data.get('actor_type') == "classic_user":
            if not check_if_auth_service():
                if not app.config.get('AUTH_STANDALONE'):
                    # :flow: 03-03(|POST|04-01) "Send request on auth service registration endpoint"
                    data['service_uuid'] = app.config['SERVICE_UUID']
                    data['signature'] = sign_data(app.config['SERVICE_PRIVATE_KEY'], json_dumps(data, sort_keys=True))
                    # :flow: 03-03(|POST|04-01) "Send request on auth service registration endpoint"
                    response = requests.post(urljoin(get_auth_domain(), '/auth/'), json=data,
                                             headers=get_language_header())
                    response_data = response.json()
                    # :flow: 03-04(03-05) "Response from auth"
                    if response.ok:
                        apt54 = json.loads(response_data.pop('apt54'))
                        query = "SELECT EXISTS(SELECT 1 FROM actor WHERE uuid = %s)"
                        values = [apt54.get('user_data').get('uuid')]
                        exists = app.db.fetchone(query, values).get('exists')
                        if not exists:
                            # :flow: 03-05(03-06) "Create user on client service with data from auth service"
                            try:
                                query = "INSERT INTO actor SELECT * FROM jsonb_populate_record(null::actor, jsonb %s)"
                                values = [json_dumps(apt54.get('user_data'))]
                                app.db.execute(query, values)
                            except Exception as e:
                                print('Exception on creating user! %s' % e)
                                print_error_cli(message="Error with creating user. "
                                                        "core.auth_view.ClientAuthView - POST.\n apt54 - %s" % apt54)
                                response = create_response_message(message=_("Some error occurred while creating actor. "
                                                                             "Please try again or contact "
                                                                             "the administrator."), error=True)
                                return make_response(jsonify(response), 400)
                        session_token = create_session(apt54, depended_info=data.get("depended_services"))
                        if isinstance(session_token, dict) and session_token.get('error'):
                            return make_response(jsonify(session_token), 403)

                        if session_token and app.config.get('SESSION_STORAGE', None) == 'SESSION' or app.config.get(
                                'SESSION_STORAGE') is None:
                            session['session_token'] = session_token

                        response_data['session_token'] = session_token

                    return make_response(jsonify(response_data), response.status_code)

            response, status = self.authorization_classic_user(data)
            if response.get('session_token') and app.config.get('SESSION_STORAGE', None) == 'SESSION' \
                    or app.config.get('SESSION_STORAGE') is None:
                session['session_token'] = response.get('session_token')

            return make_response(jsonify(response), status)

        if data.get('step', None) and data.get('step', None) == 1:
            apt54 = data.get('apt54') if isinstance(data.get('apt54'), dict) else json.loads(data.get('apt54'))
            if not isinstance(apt54.get('user_data'), dict) or not apt54.get('user_data'):
                # There is no user info in apt54
                print_error_cli(message="Error with apt54 on step 1. "
                                        "core.auth_view.ClientAuthView - POST.\n apt54 - %s" % apt54)
                response = create_response_message(message=_("Your authentication token is invalid. "
                                                             "Please contact the administrator."), error=True)
                return response, 400

            salt = create_new_salt({"uuid": apt54['user_data'].get('uuid')}, salt_for='authentication')

            if not salt:
                print_error_cli(message="Error with creating salt. core.auth_view.ClientAuthView - POST.\n "
                                        "salt - %s, user_data - %s" % (salt, apt54.get('user_data')))
                response = create_response_message(message=_("There is no verification data based on received data."),
                                                   error=True)
                return make_response(jsonify(response), 400)

            response = dict(
                salt=salt
            )
            if app.config.get("DEPENDED_SERVICES"):
                depended_services = {
                    name: data for name, _ in app.config.get("DEPENDED_SERVICES").items()
                }
                depended_services_info = self.get_depended_services_info(
                    depended_services
                )
                response.update({
                    "depended_services": depended_services_info,
                })
            return make_response(jsonify(response), 200)

        # :flow: 07-03(07-04) "Authorization with apt54"
        response, status = self.authorization(data)
        if status == 200:
            uuid = json.loads(response['apt54']).get('user_data').get('uuid')
            salt = update_salt_data(uuid, data.get('qr_token'))
            if not salt:
                print('Error with salt updating')

        sid = get_user_sid(data.get('qr_token'))

        if status == 200 and sid:
            service_response = dict(
                message=_("You are successfully authorized.")
            )
            emit('auth status', service_response, room=sid, namespace='/')
        elif sid:
            emit('auth status', response, room=sid, namespace='/')

        if data.get("depended_services"):
            depended_services_info = self.get_depended_services_info(
                data.get("depended_services")
            )
            response.update({
                "depended_services": depended_services_info,
            })

        if status == 200:
            # TODO: add expires at Doc:http://flask.pocoo.org/docs/1.0/api/#flask.Response.set_cookie
            # res.set_cookie("session_token", response.get('session_token'))
            if app.config.get('SESSION_STORAGE', None) == 'SESSION' or app.config.get('SESSION_STORAGE') is None:
                session['session_token'] = response.get('session_token')

            return make_response(jsonify(response), status)
        return make_response(jsonify(response), status)

    def get_depended_services_info(self, authorized_info):
        depended_services_info = dict()
        for name, domain in app.config.get("DEPENDED_SERVICES").items():
            service_info = requests.post(
                urljoin(domain, "/auth/"),
                json=authorized_info.get(name)
            )
            depended_services_info.update(
                {
                    name: service_info.json()
                }
            )
        return depended_services_info

    @staticmethod
    def authorization(data: dict):
        """
        Authorization. Check signed salt and if everything is good we generate session token.
        If user does not exists on current service, we create user with his apt54
        :param data: dictionary with apt54 and signed salt
        :return: response, status: response - dictionary with session_token of error=True flag with error message,
         status - http code
        :flow: 07-04(07-05) "Validate received data"
        """
        updated = False
        signed_salt = data.get('signed_salt')
        apt54 = data.get('apt54') if isinstance(data.get('apt54'), dict) else json.loads(data.get('apt54'))
        qr_token = data.get('qr_token')
        step = data.get('step', None)

        if not apt54 or not signed_salt or (not step == 2 and not qr_token):
            # There is no uuid or signed salt. Not full data set
            print_error_cli(message="Wrong data was sent. core.auth_view.APT54View - authentication.\n "
                                    "apt54 - %s, signed_salt not exists - %s, "
                                    "step - %s, qr_token - %s" % (apt54, not signed_salt, step, qr_token))
            response = create_response_message(message=_("Invalid request data."), error=True)
            return response, 400

        if not isinstance(apt54.get('user_data'), dict) or not apt54.get('user_data'):
            # There is no user info in apt54
            print_error_cli(message="Error with apt54. core.auth_view.ClientAuthView - authorization.\n "
                                    "apt54 - %s" % apt54)
            response = create_response_message(message=_("Your authentication token is invalid. "
                                                         "Please contact the administrator."), error=True)
            return response, 400

        uuid = apt54['user_data'].get('uuid')
        if step:
            salt = get_user_salt({"uuid": uuid}, salt_for='authentication')
        else:
            salt = get_user_salt({'qr_token': qr_token, 'uuid': uuid}, salt_for='authentication')

        if not salt:
            # There is no salt generated for that public key
            print_error_cli(message="Error with getting salt. core.auth_view.ClientAuthView - authorization.\n "
                                    "apt54 - %s" % apt54)
            response = create_response_message(message=_("There is no verification data based on received data. \n "
                                                         "Please get new QR code."),
                                               error=True)
            return response, 400

        # :flow: 07-05(07-06) "Getting user public key </br> and keys if they were regenerated"
        initial_key, secondary_keys = get_public_key(uuid)

        # :flow: 07-06?(|true|07-08,|false|07-07) "User have public keys"
        if not initial_key and not secondary_keys:
            # User has no public key
            # :flow: 07-07(07-08) "Get public key from apt54"
            initial_key = apt54['user_data'].get('initial_key')
            if not initial_key:
                print_error_cli(message="Error with getting initial_key, even in apt54. "
                                        "core.auth_view.ClientAuthView - authorization.\n "
                                        "initial_key - %s" % initial_key)
                response = create_response_message(message=_("There is no your public key for your actor. "
                                                             "Please contact the administrator."), error=True)
                return response, 400

        # :flow: 07-08?(|true|07-09,|false|07-19) "Verify signed salt with primary public key"
        if verify_signature(initial_key, signed_salt, salt):
            # Signature verification passed with initial key
            # :flow: 07-09(07-10) "Verify auth signature in apt54"
            if not verify_apt54(apt54):
                print_error_cli(message="APT54 is invalid. core.auth_view.ClientAuthView - authorization.\n "
                                        "apt54 - %s" % apt54)
                response = create_response_message(message=_("Your authentication token is invalid. Please try again "
                                                             "or contact the administrator."), error=True)
                return response, 400

            # :flow: 07-10?(|expired|07-11,|not expired|07-12) "Verify apt54 expiration date"
            if apt54_expired(apt54.get('expiration')):
                # APT54 expired
                # :flow: 07-11(07-13) "Getting apt54 from auth"
                if app.config.get('AUTH_STANDALONE'):
                    apt54, status_code = get_apt54_locally(uuid=uuid)
                else:
                    apt54, status_code = get_apt54(uuid=uuid)
                if status_code == 452:
                    print_error_cli(message="Error with getting APT54. There is no such actor uuid -%s. "
                                            "core.auth_view.ClientAuthView - authorization.\n "
                                            "result - %s" % (uuid, apt54))
                    response = create_response_message(
                        message=_("There is no such actor. Please try again or contact the administrator."), error=True)
                    return response, 400
                elif not apt54:
                    print_error_cli(message="Error with getting APT54. Auth is unreachable. uuid - %s "
                                            "core.auth_view.ClientAuthView - authorization.\n "
                                            "result - %s" % (uuid, apt54))
                    response = create_response_message(message=_("Auth service is unreachable. Please try again or "
                                                                 "contact the administrator."), error=True)
                    return response, 400
                elif status_code == 200:
                    updated = True
                else:
                    print_error_cli(message="Error with getting APT54. APT54 expired. uuid - %s "
                                            "core.auth_view.ClientAuthView - authorization.\n "
                                            "result - %s" % (uuid, apt54))
                    response = create_response_message(
                        message=_("Your token expired and there is some error occurred while updating it. "
                                  "Please try again or contact the administrator."), error=True)
                    return response, 400

            # :flow: 07-12(07-13) "Trying update apt54 if it was not expired"
            if not updated:
                if app.config.get('AUTH_STANDALONE'):
                    updated_apt54, status_code = get_apt54_locally(uuid=uuid)
                else:
                    updated_apt54, status_code = get_apt54(uuid=uuid)
                if status_code == 452:
                    print_error_cli(message="Error with getting APT54. There is no such actor uuid -%s. "
                                            "core.auth_view.ClientAuthView - authorization.\n "
                                            "result - %s" % (uuid, apt54))
                    response = create_response_message(
                        message=_("There is no such actor. Please try again or contact the administrator."), error=True)
                    return response, 400
                elif not apt54:
                    print_error_cli(message="Error with getting APT54. Auth is unreachable. uuid - %s "
                                            "core.auth_view.ClientAuthView - authorization.\n "
                                            "result - %s" % (uuid, apt54))
                    response = create_response_message(message=_("Auth service is unreachable. Please try again or "
                                                                 "contact the administrator."), error=True)
                    return response, 400
                elif status_code == 200:
                    apt54 = updated_apt54
                    updated = True
                else:
                    print_error_cli(message="Error with getting APT54. APT54 expired. uuid - %s "
                                            "core.auth_view.ClientAuthView - authorization.\n "
                                            "result - %s" % (uuid, apt54))
                    response = create_response_message(
                        message=_("Your token expired and there is some error occurred while updating it. "
                                  "Please try again or contact the administrator."), error=True)
                    return response, 400

            # :flow: 07-13?(|true|07-14,|false|07-15) "Actor exists"
            if not actor_exists(uuid):
                # :flow: 07-15(07-14) "Create actor based on apt54"
                if not create_actor(apt54):
                    # Error while creating user
                    print_error_cli(message="Error with creating user. "
                                            "core.auth_view.ClientAuthView - authorization.\n apt54 - %s" % apt54)
                    response = create_response_message(message=_("Some error occurred while creating actor. "
                                                                 "Please try again or contact the administrator."),
                                                       error=True)
                    return response, 400

            # :flow: 07-14(07-16) "Generate session token"
            response = create_session(apt54, auxiliary_token=data.get('qr_token'), depended_info=data.get("depended_services"))
            if isinstance(response, dict) and response.get('error'):
                return response, 403

            session_token = response
            if not session_token:
                print_error_cli(message="Error with creating session_token. "
                                        "core.auth_view.ClientAuthView - authorization.\n session_token- %s" % response)
                response = create_response_message(message=_("Some error occurred while creating session. "
                                                             "Please try again or contact the administrator."),
                                                   error=True)
                status = 400
            else:
                # :flow: 07-16?(|true|07-17,|false|07-18) "Apt54 was updated"
                if updated:
                    # :flow: 07-17(07-18) "Update user info based on updated apt54"
                    update_user(apt54)

                status = 200
                response = dict(
                    apt54=json_dumps(apt54),
                    session_token=session_token
                )
            # :flow: 07-18 "Return response with session token and apt54"
            return response, status
        else:
            # :flow: 07-19?(|false|07-20,|true|07-21) "Service use only primary key"
            if app.config.get('PRIMARY_KEY_ONLY'):
                # Important service uses only primary initial key
                # :flow: 07-21 "Error response"
                print_error_cli(message="Signature verification error Because PRIMARY_KEY_ONLY is True and "
                                        "verification by initial_key failed. "
                                        "core.auth_view.ClientAuthView - authorization.\n ")
                response = create_response_message(message=_("Signature verification failed."), error=True)
                return response, 400

            if secondary_keys:
                for public_key in secondary_keys:
                    # Check signature with secondary generated keys
                    # :flow: 07-20?(|true|07-09,|false|07-21) "Verify salt signature with secondary keys"
                    if verify_signature(public_key, signed_salt, salt):
                        if apt54_expired(apt54.get('expiration')):
                            # APT54 expired
                            if app.config.get('AUTH_STANDALONE'):
                                apt54, status_code = get_apt54_locally(uuid=uuid)
                            else:
                                apt54, status_code = get_apt54(uuid=uuid)
                            if status_code == 452:
                                print_error_cli(message="Error with getting APT54. There is no such actor uuid -%s. "
                                                        "core.auth_view.ClientAuthView - authorization.\n "
                                                        "result - %s" % (uuid, apt54))
                                response = create_response_message(
                                    message=_("There is no such actor. Please try again or contact the administrator."),
                                    error=True)
                                return response, 400
                            elif not apt54:
                                print_error_cli(message="Error with getting APT54. Auth is unreachable. uuid - %s "
                                                        "core.auth_view.ClientAuthView - authorization.\n "
                                                        "result - %s" % (uuid, apt54))
                                response = create_response_message(message="Auth service is unreachable. "
                                                                           "Please try again or contact "
                                                                           "the administrator.", error=True)
                                return response, 400
                            elif status_code == 200:
                                updated = True
                            else:
                                print_error_cli(message="Error with getting APT54. APT54 expired. uuid - %s "
                                                        "core.auth_view.ClientAuthView - authorization.\n "
                                                        "result - %s" % (uuid, apt54))
                                response = create_response_message(
                                    message=_("Your token expired and there is some error occurred while updating it. "
                                              "Please try again or contact the administrator."), error=True)
                                return response, 400

                        if not updated:
                            if app.config.get('AUTH_STANDALONE'):
                                updated_apt54, status_code = get_apt54_locally(uuid=uuid)
                            else:
                                updated_apt54, status_code = get_apt54(uuid=uuid)
                            if status_code == 452:
                                print_error_cli(message="Error with getting APT54. There is no such actor uuid -%s. "
                                                        "core.auth_view.ClientAuthView - authorization.\n "
                                                        "result - %s" % (uuid, apt54))
                                response = create_response_message(
                                    message=_("There is no such actor. Please try again or contact the administrator."),
                                    error=True)
                                return response, 400
                            elif not apt54:
                                print_error_cli(message="Error with getting APT54. Auth is unreachable. uuid - %s "
                                                        "core.auth_view.ClientAuthView - authorization.\n "
                                                        "result - %s" % (uuid, apt54))
                                response = create_response_message(
                                    message=_("Auth service is unreachable. Please try again or "
                                              "contact the administrator."), error=True)
                                return response, 400
                            elif status_code == 200:
                                apt54 = updated_apt54
                                updated = True
                            else:
                                print_error_cli(message="Error with getting APT54. APT54 expired. uuid - %s "
                                                        "core.auth_view.ClientAuthView - authorization.\n "
                                                        "result - %s" % (uuid, apt54))
                                response = create_response_message(
                                    message=_("Your token expired and there is some error occurred while updating it. "
                                              "Please try again or contact the administrator."), error=True)
                                return response, 400

                        response = create_session(apt54, auxiliary_token=data.get('qr_token'), depended_info=data.get("depended_services"))
                        if isinstance(response, dict) and response.get('error'):
                            return response, 403

                        session_token = response
                        if not session_token:
                            print_error_cli(message="Error with creating session_token. "
                                                    "core.auth_view.ClientAuthView - authorization.\n "
                                                    "session_token - %s, uuid - %s" % (response, uuid))
                            response = create_response_message(message=_("Some error occurred while creating session. "
                                                                         "Please try again or contact "
                                                                         "the administrator."),
                                                               error=True)
                            status = 400
                        else:
                            if updated:
                                update_user(apt54)

                            status = 200
                            response = dict(
                                apt54=json_dumps(apt54),
                                session_token=session_token
                            )
                        return response, status

        print_error_cli(message="Signature verification failed with both keys - initial and secondary. "
                                "core.auth_view.ClientAuthView - authorization.\n ")
        response = create_response_message(message=_("Signature verification failed."), error=True)
        return response, 400

    def authorization_classic_user(self, data: dict):
        """
        Authorization classic user.
        :param data: dictionary with actor_type,email and password
        :return: response, status: response - dictionary with session_token of error=True flag with error message,
         status - http code
        """

        password = data.get('password')
        email = data.get('email')

        result = self.check_if_from_client_service(data)
        if result.get('from_service'):
            if result.get('error'):
                result.pop('from_service')
                return result, 400

        if not password or not email:
            # There is no user_password or email. Not full data set
            print_error_cli(message="Wrong data was sent. "
                                    "core.auth_view.ClientAuthView - authorization_classic_user.\n "
                                    "email - %s, password not exists - %s" % (email, not password))
            response = create_response_message(message=_("Invalid request data."), error=True)
            return response, 400

        try:
            validate_email(email)
        except Auth54ValidationError as e:
            response = create_response_message(message=_("Email you have inputted is invalid. Please check it."),
                                               error=True)
            return response, 400

        user = app.db.fetchone("""SELECT * FROM actor WHERE uinfo ->> 'email' = %s AND actor_type = 'classic_user'""",
                               [email])

        if not user:
            # There is no user with such email in database.
            print_error_cli(message="Error with getting user. "
                                    "core.auth_view.ClientAuthView - authorization_classic_user.\n email - %s" % email)
            response = create_response_message(message=_("There is no actor with such email. Please check it."),
                                               error=True)
            return response, 400

        hashed_password = user['uinfo'].get('password')

        if hashed_password != hash_md5(password):
            response = create_response_message(message=_("Password verification failed."), error=True)
            return response, 400
        if app.config.get('AUTH_STANDALONE'):
            apt54, status_code = get_apt54_locally(uuid=user.get('uuid'))
        else:
            apt54, status_code = get_apt54(uuid=user.get('uuid'))
        if status_code == 452:
            print_error_cli(message="Error with getting APT54 for classic user. There is no such actor uuid -%s. "
                                    "core.auth_view.ClientAuthView - authorization.\n "
                                    "result - %s" % (user.get('uuid'), apt54))
            response = create_response_message(
                message=_("There is no such actor. Please try again or contact the administrator."),
                error=True)
            return response, 400
        elif not apt54:
            print_error_cli(message="Error with getting APT54 for classic user. Auth is unreachable. uuid - %s "
                                    "core.auth_view.ClientAuthView - authorization.\n "
                                    "result - %s" % (user.get('uuid'), apt54))
            response = create_response_message(
                message=_("Auth service is unreachable. Please try again or "
                          "contact the administrator."), error=True)
            return response, 400
        elif status_code == 200:
            pass
        else:
            print_error_cli(message="Error with getting APT54 for classic user. APT54 expired. uuid - %s "
                                    "core.auth_view.ClientAuthView - authorization.\n "
                                    "result - %s" % (user.get('uuid'), apt54))
            response = create_response_message(
                message=_("Your token expired and there is some error occurred while updating it. "
                          "Please try again or contact the administrator."), error=True)
            return response, 400

        if not result.get('from_service'):
            response = create_session(apt54, depended_info=data.get("depended_services"))
        else:
            response = None

        if isinstance(response, dict) and response.get('error'):
            return response, 403

        session_token = response
        response = dict(
            apt54=json_dumps(apt54),
            session_token=session_token
        )
        return response, 200


class SaveSession(MethodView):

    def post(self):
        """
        Save session in cookies with flask session module.
        :return: JSON with message
        """
        if (not request.is_json
            or not request.json.get('session_token') 
            or not isinstance(request.json.get('session_token'), str)):
            response = create_response_message(message=_("Invalid request type."), error=True)
            return make_response(jsonify(response), 422)

        session_token = request.json.get('session_token')

        if app.db.fetchone("""SELECT EXISTS(SELECT 1 FROM service_session_token WHERE session_token = %s)""",
                           [session_token]).get('exists'):
            session['session_token'] = session_token
        else:
            print('Unknown session token - %s' % session_token)

        response = dict(
            message=_("Session token successfully saved.")
        )
        return make_response(jsonify(response), 200)


class GetSession(MethodView):

    def post(self):
        """
        Save session in cookies with flask session module.
        :return: JSON with message
        """
        if not request.is_json:
            response = create_response_message(
                message=_("Invalid request type."), error=True)
            return make_response(jsonify(response), 422)

        if request.json.get("qr_code"):
            session_token = get_session_token_by_auxiliary(request.json.get('qr_token'))
            if not session_token:
                if hasattr(request, 'sid'):
                    sid = request.sid
                    set_actor_sid(sid, request.json)
                    session_token = dict(
                        message=_("There is no session token.")
                    )
                else:
                    session_token = dict(
                        message=_("Some error occurred while getting socket id.")
                    )
            response = session_token

        temporary_session = request.json.get('temporary_session')

        if temporary_session:
            if app.db.fetchone("""SELECT EXISTS(SELECT 1 FROM temporary_session WHERE temporary_session = %s)""",
                               [temporary_session]).get('exists'):
                session_token = get_session_token_by_auxiliary(
                    temporary_session)
                if session_token:
                    app.db.execute("""UPDATE service_session_token SET auxiliary_token = NULL WHERE auxiliary_token = %s""",
                                   [temporary_session])

                delete_temporary_session(temporary_session)

                response = session_token

        return make_response(jsonify(response), 200)


class AuthorizationView(MethodView):

    @cross_origin()
    def get(self, **kwargs):
        """
        Get login template.
        If in SESSION TOKEN is SESSION, automatically adding js, css scripts from static folder.
        :param kwargs: dict. OPTIONAL. Example:
        {
            "save_session_url": https://example.com/save or /save/ or url_for('save'),
            "get_qr_url": https://example.com/qr or /qr/ or url_for('qr'),
            "auth_sso_url": https://example.com/sso or /sso/ or url_for('sso'),
            "registration_url": https://example.com/registration or /registration/ or url_for('registration'),
            "authentication_url": https://example.com/authentication or /authentication/ or url_for('authentication')
        }
        :return: template
        """
        services = self.create_services()
        ios_qr, android_qr = self.create_platform_qrs()
        scripts = self.create_scripts(**kwargs)
        language_information, current_language = self.define_language()
        return render_template('auth.html', ios_app=ios_qr, android_app=android_qr,
                               services=services.get('services'), scripts=scripts,
                               language_information=language_information, current_language=current_language)

    def create_scripts(self, **kwargs):
        if app.config['SESSION_STORAGE'] == 'SESSION':
            js_folder = auth_submodule.static_folder + '/js/'
            css_folder = auth_submodule.static_folder + '/css/'
            js_parts = self.load_parts(js_folder+"js_fragments.json",
                                       js_folder+"js_fragments/")
            js_libs_names = ["socketio.js", "qrLib.js"]

            locals().update(
                self.crate_locals(
                    **kwargs
                )
            )
            locals().update(js_parts)
            variables = self.clear_variables(
                wrong_name="self", variables=locals()
            )

            part_creators, variable_creators = self.collect_creators()
            scripts = StaticBuilder(
                js_folder_path=js_folder,
                libs_names=js_libs_names,
                css_folder_path=css_folder,
                part_creators=part_creators,
                variable_creators=variable_creators,
                **variables
            ).build()

        else:
            scripts = dict(
                css="",
                js=""
            )
        return scripts

    def load_parts(self, path, js_fragments_folder):
        with open(path, 'r', encoding='utf-8') as f:
            parts = json.load(f)
        self.load_fragments(parts, js_fragments_folder)
        return parts

    def load_fragments(self, fragments_names, js_fragments_folder):
        for fragment_name, file_name in fragments_names.items():
            with open(js_fragments_folder + file_name, "r") as file:
                fragments_names[fragment_name] = file.read()

    def collect_creators(self):
        part_creators=[
            self.create_make_sso_login_function,
            self.create_make_classic_login_function,
            self.create_save_session_function,
            self.create_authorization_response_event,
            self.create_check_cookie_function,
            self.create_update_qr_function,
            self.create_after_save_session_function,
        ]
        variable_creators=[
            self.create_authentication_qr_token
        ]
        return part_creators, variable_creators

    def clear_variables(self, wrong_name, variables):
        variables = {
            name: value
            for name, value in variables.items()
            if name != wrong_name
        }
        return variables

    def create_platform_qrs(self):
        ios_qr = base64.b64encode(QRCodeView().generate_qr_image(
            ERP_APP_URL.get('ios')).getvalue()).decode()
        android_qr = base64.b64encode(QRCodeView().generate_qr_image(
            ERP_APP_URL.get('android')).getvalue()).decode()
        return ios_qr, android_qr

    def create_services(self):
        services = dict(services=[])
        if not app.config.get('AUTH_STANDALONE'):
            url = urljoin(get_auth_domain(), '/services_info/')
            try:
                response = requests.get(url, headers=get_language_header())
                services = json.loads(response.content)
            except Exception as e:
                services = dict(services=[])
        return services

    def create_content(self, data):
        response = QRCodeView().get(data=data)
        content = response.json
        return content

    def get_service_domain(self):
        query = """SELECT uinfo->>'service_domain' AS service_domain FROM actor WHERE uuid = %s"""
        service_domain = app.db.fetchone(
            query, [app.config.get('SERVICE_UUID')])
        if not service_domain:
            raise ActorNotFound
        return service_domain

    def create_urls(self, service_domain, **kwargs):
        registration_url = kwargs.get('registration_url') \
            if kwargs and kwargs.get('registration_url') \
            else urljoin(
                service_domain.get('service_domain'),
                url_for('auth_submodule.reg')
            )
        authentication_url = kwargs.get('authentication_url') \
            if kwargs and kwargs.get('authentication_url') \
            else urljoin(
                service_domain.get('service_domain'), 
                url_for('auth_submodule.auth')
            )
        return registration_url, authentication_url

    def define_language(self):
        language_information = app.config.get('LANGUAGES_INFORMATION', [])
        current_language = None
        for language in language_information:
            if language.get('code') == get_service_locale():
                current_language = language

        if not current_language:
            current_language = {"code": "en", "name": "English"}
        return language_information, current_language

    def crate_locals(
        self,
        **kwargs
        ):
        service_domain = self.get_service_domain()
        registration_url, authentication_url = self.create_urls(
            service_domain=service_domain,
            **kwargs
        )
        standalone = app.config.get("AUTH_STANDALONE")
        redirect_url = self._get_redirect_url()
        depended_services = app.config.get("DEPENDED_SERVICES")
        current_name=app.config.get("SERVICE_NAME")
        current_domain=app.config.get("SERVICE_DOMAIN")
        reload_part = "\n window.location.replace(\"{}\");".format(redirect_url)
        save_session_url = kwargs.get('save_session_url') if kwargs and kwargs.get('save_session_url') \
            else url_for('auth_submodule.save_session')
        save_session_url = app.config.get("SERVICE_DOMAIN") + save_session_url
        backend_domain = app.config.get("SERVICE_DOMAIN")
        socket_path = app.config.get('SOCKET_PATH', '/socket')
        language_cookie_key = app.config.get('LANGUAGE_COOKIE_KEY', 'language')
        base_error_message_js = _("Some error has occurred, please contact the administrator")
        if not app.config.get('AUTH_STANDALONE'):
            registration_content, authentication_content = \
                self.create_registration_authorization_content(
                    authentication_url, registration_url
                )
            registration_qr_token = dict(
                qr_token=registration_content.get("qr_token"),
                qr_type="registration"
            )
            authentication_qr_token = self.create_authentication_qr_token(authentication_content).get('authentication_qr_token')
            get_qr_url = kwargs.get('get_qr_url') if kwargs and kwargs.get('get_qr_url') \
                else url_for('auth_submodule.qr-code')
            get_qr_url = app.config.get("SERVICE_DOMAIN") + get_qr_url
            auth_sso_url = kwargs.get('auth_sso_url') if kwargs and kwargs.get('auth_sso_url') \
                else url_for('auth_submodule.auth-sso')
        return locals()

    def _get_redirect_url(self):
        redirect_url = request.referrer
        if redirect_url:
            url_parts = redirect_url.split("/")
            redirect_url = url_parts[0] + "//" + url_parts[2]
        else:
            redirect_url = app.config.get("REDIRECT_URL")
        return redirect_url

    def create_registration_authorization_content(self, authentication_url, registration_url):
        registration_data = dict(
            qr_type='registration',
            registration_url=registration_url,
            authentication_url=authentication_url
        )
        authentication_data = dict(
            qr_type='authentication',
            authentication_url=authentication_url
        )
        registration_content = self.create_content(data=registration_data)
        authentication_content = self.create_content(data=authentication_data)
        return registration_content, authentication_content

    @staticmethod
    def create_make_sso_login_function(
        depended_services: dict = {},
        current_domain: str = "",
        redirect_url: str = "",
        make_sso_login_base: str = "",
        make_sso_login_fetch_part: str = "",
        make_sso_login_form_part: str = "",
        **kwargs
    ):
        make_sso_login_base = \
            make_sso_login_base % (redirect_url, current_domain, "%s")
        for name, domain in depended_services.items():
            make_sso_login_base = \
                make_sso_login_base % \
                make_sso_login_fetch_part % \
                (domain, name, "%s")
        make_sso_login_base = \
            make_sso_login_base % \
            make_sso_login_form_part
        return make_sso_login_base

    @staticmethod
    def create_make_classic_login_function(
        depended_services: dict = {},
        current_name: str = "",
        current_domain: str = "",
        make_classic_login_base: str = "",
        make_classic_login_fetch_part: str = "",
        **kwargs
    ) -> str:
        depended_services = dict(depended_services)
        depended_services.update(
            {
                current_name: current_domain,
            }
        )
        for name, domain in depended_services.items():
            make_classic_login_base = \
                make_classic_login_base % \
                make_classic_login_fetch_part % \
                (domain, name.capitalize(), "%s")
        make_classic_login_base = make_classic_login_base \
            % "\nafterSaveSession()"
        return make_classic_login_base

    @staticmethod
    def create_save_session_function(
        depended_services: dict = {},
        current_name: str = "",
        current_domain: str = "",
        save_session_base: str = "",
        save_session_fetch_part: str = "",
        **kwargs
    ) -> str:
        save_session_base = save_session_base % \
            (current_domain, "",current_name.capitalize(),"", "%s")
        for name, domain in depended_services.items():
            save_session_base = \
                save_session_base % \
                save_session_fetch_part % (
                domain, name.lower() + "_",
                name.capitalize(), name.lower() + "_",
                "%s"
            )
        save_session_base = save_session_base \
            % "\nafterSaveSession()"
        return save_session_base

    @staticmethod
    def create_authorization_response_event(
        depended_services: dict = {},
        current_name: str = "",
        authorization_response_event: str = "",
        **kwargs
    ):
        if not app.config.get('AUTH_STANDALONE'):
            cookie = ""
            if current_name:
                cookie += "\n" + "document.cookie = \"" \
                    + current_name.capitalize() + "=\"+" \
                    + "msg." + "session_token" + "+'; path=/'"
            for name, _ in depended_services.items():
                cookie += "\n" + "document.cookie = \"" \
                    + name.capitalize() + "=\"+" \
                    + "msg." + name.lower() + "_session_token" + "+'; path=/'"
            authorization_response_event = \
                authorization_response_event % cookie
            return authorization_response_event
        return ""

    @staticmethod
    def create_check_cookie_function(
        depended_services: dict = {},
        current_name: str = "",
        check_cookie_base: str = "",
        **kwargs
    ):
        if not app.config.get('AUTH_STANDALONE'):
            cookie_names = ""
            temporary_session = ""
            if current_name:
                cookie_names += "\n" + "deleteCookie(\"temporary_session\")"
                temporary_session += "temporary_session: getCookie(\"temporary_session\")"
            for name, _ in depended_services.items():
                cookie_names += "\n" + "deleteCookie(\"temporary_session_" \
                    + name.lower() + "\")"
                temporary_session += \
                    ",\ntemporary_session_" + name.lower() + \
                    ":getCookie(\"temporary_session_" + name.lower() + "\")"
            check_cookie_base = check_cookie_base % \
                (temporary_session, cookie_names, current_name.capitalize())
            return check_cookie_base
        return ""

    @staticmethod
    def create_authentication_qr_token(
        authentication_content: dict = {},
        **kwargs
    ):
        authentication_qr_token = {
            "qr_token": authentication_content.get("qr_token"),
            "qr_type": "authentication"
        }
        if authentication_content.get("depended_services"):
            authentication_qr_token.update({
                "depended_services": {}
            })
            for name, data in authentication_content.get("depended_services").items():
                authentication_qr_token.get("depended_services", {}).update(
                    {
                        name: {
                            "qr_token": data.get("qr_token"),
                            "qr_type": "authentication"
                        }
                    }
                )
        return {"authentication_qr_token": authentication_qr_token}

    @staticmethod
    def create_update_qr_function(
        update_qr_function: str = "",
        get_qr_url: str = "",
        **kwargs
        ):
        if not app.config.get('AUTH_STANDALONE'):
            update_qr_function = update_qr_function % (get_qr_url, get_qr_url, kwargs['registration_qr_token'],
                                     kwargs['authentication_qr_token'],
                                     kwargs['authentication_content'], kwargs['registration_content'])
            return update_qr_function
        return ""

    @staticmethod
    def create_after_save_session_function(
        after_save_session_function: str,
        reload_part: str,
        **kwargs
    ):
        return after_save_session_function % reload_part
