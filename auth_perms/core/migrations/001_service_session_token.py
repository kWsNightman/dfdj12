from . import base


class Migration(base.BaseMigration):
    """
    Create service_session table.
    """
    table_name = "service_session_token"
    forwards_query = f"""
        CREATE TABLE {table_name} (
            session_token character varying(32) UNIQUE,
            uuid uuid references actor(uuid) ON DELETE CASCADE,
            created timestamp DEFAULT (now() at time zone 'utc'),
            token_type character varying(64) DEFAULT 'session_token',
            qr_token character varying(32) DEFAULT '',
            apt54 jsonb
        )
        """

    backwards_query = f"""
        DROP TABLE {table_name}
    """
