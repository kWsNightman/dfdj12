from . import base


class Migration(base.BaseMigration):
    """
    Create invite_link_temp table
    """
    table_name = "invite_link_temp"

    forwards_query = f"""
        ALTER TABLE actor DROP COLUMN IF EXISTS private_initial_key;  
        """

    backwards_query = f""""""
