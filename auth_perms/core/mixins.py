class UserMixin(object):
    """
    Default object for representing user
    """
    def __init__(self, user):
        self.user = user

    @property
    def is_authenticated(self):
        return True

    @property
    def is_active(self):
        return True

    @property
    def is_anonymous(self):
        return False


class AnonymousUserMixin(object):
    """
    Default object for representing an anonymous user
    """
    def __init__(self):
        self.user = None

    @property
    def is_authenticated(self):
        return False

    @property
    def is_active(self):
        return False

    @property
    def is_anonymous(self):
        return True

