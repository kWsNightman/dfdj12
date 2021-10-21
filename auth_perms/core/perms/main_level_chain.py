from werkzeug.exceptions import Unauthorized

from .base import BasePerms
from .biom_level_chain import BiomLevelChain


class MainLevelChain(BasePerms):
    """
    Main flow perms check
    """
    def permissions_check(self):
        if self.user.is_root:
            return True

        if self.user.is_banned:
            raise Unauthorized

        if self.user.is_admin:
            return True

        biom_level = BiomLevelChain(user=self.user, action_id=self.action_id, source_class=self.source_class)

        if not biom_level.check():
            return False

        return True
