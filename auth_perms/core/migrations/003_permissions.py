from . import base


class Migration(base.BaseMigration):
    """
    Create permissions table.
    """

    table_name = "permissions"
    forwards_query = f"""

        CREATE TABLE {table_name} (
            service_id uuid references actor(uuid) ON DELETE CASCADE,
            perm_id character varying(256),
            actor_id uuid references actor(uuid) ON DELETE CASCADE,
            perm_value smallint CHECK (perm_value >= 0 AND perm_value <= 1),
            default_value smallint CHECK (default_value >= 0 AND default_value <= 1),
            perm_type character varying(64) CHECK (perm_type='simple' OR perm_type='check'),
            action_id character varying(256),
            description character varying(512),
            created timestamp DEFAULT (now() at time zone 'utc'),
            PRIMARY KEY(actor_id, perm_id)
        )
        """

    backwards_query = f"""
        DROP TABLE {table_name}
    """
