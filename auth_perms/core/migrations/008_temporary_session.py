from . import base


class Migration(base.BaseMigration):
    """
    Create service_session table.
    """
    table_name = "temporary_session"
    forwards_query = f"""
        CREATE TABLE {table_name} (
            temporary_session character varying(32) UNIQUE,
            service_uuid uuid references actor(uuid) ON DELETE CASCADE,
            created timestamp DEFAULT (now() at time zone 'utc'),
            redirect_to character varying(128),
            actor_sid character varying(32) DEFAULT ''
        )
        """

    backwards_query = f"""
        DROP TABLE {table_name}
    """
