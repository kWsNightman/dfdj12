from . import base


class Migration(base.BaseMigration):
    """
    Update service_session table.
    """
    table_name = "service_session_token"
    forwards_query = f"""
        ALTER TABLE {table_name} RENAME COLUMN qr_token TO auxiliary_token; 
        """

    backwards_query = f"""
    """
