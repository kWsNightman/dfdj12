from . import base


class Migration(base.BaseMigration):
    """
    Phantom actor table
    """
    forwards_query = f"""

        CREATE TABLE phantom_relation (
            uuid uuid UNIQUE DEFAULT uuid_generate_v4(),
            created timestamp DEFAULT (now() at time zone 'utc'),
            phantom_actor uuid references actor(uuid) ON DELETE CASCADE,
            target_actor uuid references actor(uuid) ON DELETE CASCADE
        );
    """

    backwards_query = f"""
        DROP TABLE phantom_relation CASCADE;
    """

