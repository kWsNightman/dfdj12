"""
Base class for actions. This class contains general function for some permissions.
Like comparing dates or checking some time range and other.
All actions should be inherited from BaseAction class.
"""


class BaseAction:
    """
    Base action that includes base methods for all actions
    """
    @classmethod
    def collect_all_perms(cls):
        """
        Method collects all biom permissions of current action with default values and permission type
        :return: list of dict(permission_name, description, permission type and default value)
        """
        permissions = filter(lambda perm: perm.startswith('biom_perm') or perm.startswith('entity_perm'), dir(cls))

        result = [{
            'perm_name': perm,
            'description': getattr(cls, perm).__doc__,
            'perm_type': getattr(cls, perm).action_type if hasattr(getattr(cls, perm), 'action_type') else None,
            'default_value': getattr(cls, perm).default_value if hasattr(getattr(cls, perm), 'default_value') else None,

        } for perm in permissions]
        return result
