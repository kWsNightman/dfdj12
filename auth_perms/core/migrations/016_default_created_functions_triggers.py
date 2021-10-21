from . import base


class Migration(base.BaseMigration):
    """
    Create function with trigger on update and insert for adding default created timestamp in UTC.
    Need if we are using jsonb_populate_record and jsonb_populate_recordset setting null on created.
    """
    forwards_query = f"""
        CREATE OR REPLACE FUNCTION set_default_created()
        RETURNS trigger AS
        $BODY$
        BEGIN
            IF (NEW.created IS NULL) THEN
                NEW.created := timezone('utc', now());
            END IF;
            RETURN NEW;
        END;
        $BODY$
        LANGUAGE plpgsql VOLATILE;

        CREATE TRIGGER set_default_actor_created BEFORE UPDATE OR INSERT ON actor FOR EACH ROW
        EXECUTE PROCEDURE set_default_created();
        
        CREATE TRIGGER set_default_permission_created BEFORE UPDATE OR INSERT ON permissions FOR EACH ROW
        EXECUTE PROCEDURE set_default_created();
        
        """

    backwards_query = f"""
        DROP TRIGGER set_default_actor_created ON actor CASCADE;
        DROP TRIGGER set_default_permission_created ON permissions CASCADE;
    """
