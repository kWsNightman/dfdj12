from . import base


class Migration(base.BaseMigration):
    """
    Create salt_token table.
    """
    table_name = "salt_temp"
    forwards_query = f"""
        CREATE TABLE {table_name} (
            salt character varying(256),
            created timestamp DEFAULT (now() at time zone 'utc') + interval '1 hour',
            uuid uuid references actor(uuid) ON DELETE CASCADE,
            pub_key character varying(130) DEFAULT '',
            qr_token character varying(32) DEFAULT '',
            actor_sid character varying(32) DEFAULT ''
        )
        """

    backwards_query = f"""
        DROP TABLE {table_name}
    """
