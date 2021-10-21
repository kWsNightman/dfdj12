from . import base


class Migration(base.BaseMigration):
    """
    Create invite_link_temp table
    """
    table_name = "invite_link_temp"

    forwards_query = f"""
        CREATE TABLE {table_name} (
            link_uuid uuid,
            created timestamp without time zone default (now() at time zone 'utc'),
            auxiliary_token character varying(64),
            sid character varying(64),
            service_uuid uuid references actor(uuid) ON DELETE CASCADE,
            params jsonb
        );
        """

    backwards_query = f"""
        DROP TABLE {table_name};
        """
