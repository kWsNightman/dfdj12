from flask import current_app as app

from .base import BasePerms


class BiomLevelChain(BasePerms):
    """
    Biom Level Chain permissions check
    """
    def check(self):
        if not self.simple_permissions():
            return False

        if not self.check_permissions():
            return False
        return True

    def simple_permissions(self):

        with app.db.get_cursor() as cur:

            cur.execute("SELECT COUNT(*) FROM get_biom_permissions(%s, %s, 'simple') WHERE value=0;",
                        (self.user.uuid, self.action_id))

            result = cur.fetchone()

        if result and result.get('count') != 0:
            return False
        return True

    def check_permissions(self):

        with app.db.get_cursor() as cur:

            cur.execute("SELECT * FROM get_biom_permissions(%s, %s, 'check');", (self.user.uuid, self.action_id))
            result = cur.fetchall()

        if not result:
            return True

        for permission in result:
            if permission.get('value') == 1:
                continue

            perm_function_name = permission.get('permission_id').split('/')[-1]
            module = getattr(self.source_class, perm_function_name)
            if not module():
                return False

        return True
