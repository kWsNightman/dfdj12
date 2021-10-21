from . import base


class Migration(base.BaseMigration):
    """
    Add uuid in permissions table
    """

    forwards_query = f"""
        DO $$ BEGIN
            ALTER TABLE permissions DROP CONSTRAINT permissions_pkey;
        EXCEPTION
            WHEN others THEN null;
        END $$;

        DO $$ BEGIN
            ALTER TABLE permissions ADD COLUMN uuid UUID UNIQUE DEFAULT uuid_generate_v4();
        EXCEPTION
            WHEN others THEN null;
        END $$;

        DO $$ BEGIN
            ALTER TABLE permissions ADD PRIMARY KEY (uuid);
        EXCEPTION
            WHEN others THEN null;
        END $$;
        """

    backwards_query = f""""""
