from . import base


class Migration(base.BaseMigration):
    """
    Create auth_user table.
    Trigger created for checking on INSERT or UPDATE if such public key already exists.
    Insert into database default group, and information about current service
    """
    table_name = "actor"
    forwards_query = f"""

        CREATE TABLE {table_name} (
            uuid uuid UNIQUE DEFAULT uuid_generate_v4(),
            created timestamp DEFAULT (now() at time zone 'utc'),
            root_perms_signature text DEFAULT null,
            private_initial_key character varying(64) DEFAULT null,
            initial_key character varying(130) UNIQUE,
            secondary_keys jsonb,
            uinfo jsonb,
            actor_type character varying(64) DEFAULT 'user'
        );

        DROP TRIGGER IF EXISTS validate_pub_key ON {table_name} CASCADE;
        DROP FUNCTION IF EXISTS validate_pub_key CASCADE;
        CREATE INDEX IF NOT EXISTS {table_name}_initial_key_key ON {table_name}(initial_key);
--         CREATE OR REPLACE FUNCTION validate_pub_key()
--         RETURNS trigger AS
--         $BODY$
--         DECLARE pub_key text;
--         BEGIN
--             pub_key = NEW.initial_key;
--             IF tg_op = 'INSERT' THEN
--                 IF EXISTS 
--                     (SELECT * FROM actor WHERE initial_key = pub_key) THEN
--                     RAISE EXCEPTION 'Cannot create user, because user with such public key already registered';
--                 END IF;
--             ELSIF tg_op = 'UPDATE' THEN
--                 IF EXISTS
--                     (SELECT * FROM actor WHERE initial_key = pub_key AND uuid != OLD.uuid) 
--                     THEN
--                     RAISE EXCEPTION 'Cannot update user, because user with such public key already exists';
--                 END IF;
--             END IF;
--         RETURN NEW;
--         END;
--         $BODY$
--         LANGUAGE plpgsql VOLATILE;
-- 
--         CREATE TRIGGER validate_pub_key BEFORE UPDATE OR INSERT ON actor FOR EACH ROW 
--         EXECUTE PROCEDURE validate_pub_key();
        """

    backwards_query = f"""
        DROP TABLE {table_name} CASCADE
    """
