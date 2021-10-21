from flask_babel import gettext as _
from werkzeug.exceptions import HTTPException


class Auth54ValidationError(Exception):
    """
    Simple validation error exception.
    """
    def __init__(self, message: str, status_code: int = 400) -> None:
        self.message = message
        self.status_code = status_code


class DatabaseError(Exception):
    """
    Database exception
    """
    def __init__(self, message: str = _("Database error."), status_code: int = 400) -> None:
        self.message = message
        self.status_code = status_code


class Apt54Expired(HTTPException):
    """*454* `Apt54Expired`

    Used if user apt54 expired
    """

    code = 454
    description = (
        _("Actor apt54 expired! You need update it.")
    )


class ServiceSaltError(Exception):
    """
    Error with getting salt
    """
    def __init__(self, message: str = _("Error with getting salt."), status_code: int = 400) -> None:
        self.message = message
        self.status_code = status_code


class ServiceAPT54Error(Exception):
    """
    Error with getting apt54
    """
    def __init__(self, message: str = _("Error with getting apt54."), status_code: int = 400) -> None:
        self.message = message
        self.status_code = status_code


class ServiceSessionError(Exception):
    """
    Error with getting session
    """
    def __init__(self, message: str = _("Error with getting session."), status_code: int = 400) -> None:
        self.message = message
        self.status_code = status_code


class ServiceInvalidData(Exception):
    """
    Invalid class for getting sync data
    """
    def __init__(self, message: str = _("Invalid service class."), status_code: int = 400) -> None:
        self.message = message
        self.status_code = status_code


class AuthUnavailable(Exception):
    """
    Auth service is unavailable
    """
    def __init__(self, message: str = _("Auth service is unavailable."), status_code: int = 400) -> None:
        self.message = message
        self.status_code = status_code


class AuthServiceNotRegistered(Exception):
    """
    Auth service is not registered.
    """
    def __init__(self, message: str = 'Auth service is not registered.', status_code: int = 501) -> None:
        self.message = message
        self.status_code = status_code


class ServiceRequestError(Exception):
    """
    Error with sending request on auth
    """
    def __init__(self, message: str = _("Some error occurred with sending request."), status_code: int = 400) -> None:
        self.message = message
        self.status_code = status_code


class ServiceMissGroupError(Exception):
    """
    Error when static group is missing
    """

    def __init__(self, message: str = _("Static group is missing."), status_code: int = 400) -> None:
        self.message = message
        self.status_code = status_code


class ServiceIsNotActorError(Exception):
    """
    Service is not an Actor instance
    """

    def __init__(self, message: str = _("Wrong service type."), status_code: int = 400) -> None:
        self.message = message
        self.status_code = status_code


class AuthPermsDataError(Exception):
    """
    Base auth perms data exception
    """
    def __init__(self, message: str, status_code: int = 500) -> None:
        self.message = message
        self.status_code = status_code


class BaseArgumentsError(Exception):
    """
    Base arguments exception.
    """
    def __init__(self, message: str, status_code: int = 500):
        self.message = message
        self.status_code = status_code
