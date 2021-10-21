from . import base


class Migration(base.BaseMigration):
    """
    Add column salt_for in salt_temp table, for saving action name what for salt was generated
    """

    forwards_query = f"""
        DO $$ BEGIN
            ALTER TABLE salt_temp ADD COLUMN salt_for CHARACTER VARYING(64) DEFAULT '';
        EXCEPTION
            WHEN others THEN null;
        END $$;
        """

    backwards_query = f""""""
