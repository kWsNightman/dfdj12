from . import base


class Migration(base.BaseMigration):
    """
    Create invite_link table
    """
    table_name = "invite_link"

    forwards_query = f"""
        CREATE TABLE {table_name} (
            uuid uuid UNIQUE DEFAULT uuid_generate_v4() PRIMARY KEY,
            actor uuid references actor(uuid) ON DELETE CASCADE ,
            created timestamp without time zone default (now() at time zone 'utc'),
            identifier character varying(64),
            link text,
            group_uuid uuid references actor(uuid) ON DELETE CASCADE,
            params jsonb

        );
        """

    backwards_query = f"""
        DROP TABLE {table_name};
        """
