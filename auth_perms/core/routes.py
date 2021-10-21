from . import auth_submodule
from .actor_view import ActorView

from .auth_view import AboutView
from .auth_view import APT54View
from .auth_view import AuthSSOView
from .auth_view import RegistrationView
from .auth_view import ClientAuthView
from .auth_view import QRCodeView
from .auth_view import SaveSession
from .auth_view import GetSession
from .auth_view import AuthorizationView
from .admin_view import AdminView
from .admin_view import AdminActorView
from .admin_view import AdminActorsView
from .admin_view import AdminPermissionView
from .admin_view import AdminProfileView
from .invite_link_view import GetInviteLinkInfoView
from .permission_view import PermissionView
from .phantom_actor import CreatePhantomRelationView
from .phantom_actor import DeletePhantomRelationView
from .phantom_actor import GetPhantomActorView
from .phantom_actor import SetChosenPhantomActorView


# Registration/authentication endpoints
auth_submodule.add_url_rule('/apt54/', view_func=APT54View.as_view('apt54'))  # Get APT54
auth_submodule.add_url_rule('/auth/', view_func=ClientAuthView.as_view('auth'))  # Authentication
auth_submodule.add_url_rule('/auth_authorization/', view_func=AuthSSOView.as_view('auth-sso'))  # Auth Single Sign-On
auth_submodule.add_url_rule('/authorization/', view_func=AuthorizationView.as_view('authorization'))  # Get template
auth_submodule.add_url_rule('/reg/', view_func=RegistrationView.as_view('reg'))  # Registration
auth_submodule.add_url_rule('/save_session/', view_func=SaveSession.as_view('save_session'))  # Save session in cookie
auth_submodule.add_url_rule('/get_session/', view_func=GetSession.as_view('get_session'))  # Get session with temporary session


# Auth API endpoints
auth_submodule.add_url_rule('/actor/', view_func=ActorView.as_view('actor'))  # CRUD actor from auth
auth_submodule.add_url_rule('/perms/', view_func=PermissionView.as_view('permissions'))  # CRUD permissions from auth

# Utility endpoints
auth_submodule.add_url_rule('/about/', view_func=AboutView.as_view('about'))  # Service/biom info
auth_submodule.add_url_rule('/get_qr_code/', view_func=QRCodeView.as_view('qr-code'))  # QR code generation

# Phantom endpoints
auth_submodule.add_url_rule('/create/phantom', view_func=CreatePhantomRelationView.as_view('create_phantom_relation'))
auth_submodule.add_url_rule('/delete/phantom', view_func=DeletePhantomRelationView.as_view('delete_phantom_relation'))
auth_submodule.add_url_rule('/get/phantom', view_func=GetPhantomActorView.as_view('get_phantom'))
auth_submodule.add_url_rule('/choose/phantom', view_func=SetChosenPhantomActorView.as_view('choose_phantom'))

# Temporary endpoints
auth_submodule.add_url_rule('/get_invite_link_info/', view_func=GetInviteLinkInfoView.as_view('get_invite_link_info'))

# Admin panel in auth standalone
auth_submodule.add_url_rule('/auth_admin/', view_func=AdminView.as_view('admin'))
auth_submodule.add_url_rule('/auth_admin/profile/', view_func=AdminProfileView.as_view('admin_profile'))
auth_submodule.add_url_rule('/auth_admin/actors/', view_func=AdminActorsView.as_view('admin_actors'))
auth_submodule.add_url_rule('/auth_admin/actor/<uuid>/', view_func=AdminActorView.as_view('admin_actor'))
auth_submodule.add_url_rule('/auth_admin/permissions/', view_func=AdminPermissionView.as_view('admin_permissions'))
