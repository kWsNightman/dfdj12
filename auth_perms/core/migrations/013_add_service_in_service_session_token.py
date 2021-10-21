from . import base


class Migration(base.BaseMigration):
    """
    Add service_uuid for what session is created
    """

    forwards_query = f"""
        DO $$ BEGIN
            ALTER TABLE service_session_token ADD COLUMN service_uuid UUID REFERENCES actor (uuid);
        EXCEPTION
            WHEN others THEN null;
        END $$;
        """

    backwards_query = f""""""
