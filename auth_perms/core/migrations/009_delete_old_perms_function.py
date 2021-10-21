from . import base


class Migration(base.BaseMigration):
    """
    Delete old permissions from table table.
    """
    forwards_query = f"""
    DROP FUNCTION IF EXISTS get_old_perms;
    DROP FUNCTION IF EXISTS get_new_perms;
    DROP FUNCTION IF EXISTS delete_old_permissions;

    -- Get permissions from database by service uuid
    CREATE OR REPLACE FUNCTION get_old_perms(service_uuid uuid)
      RETURNS TABLE(
        service_id uuid,
        perm_id character varying(256),
        actor_id uuid,
        perm_value smallint,
        default_value smallint,
        perm_type character varying(64),
        action_id character varying(256),
        description character varying(512),
        created timestamp,
        uuid uuid)
      RETURNS NULL ON NULL INPUT
    AS $BODY$
        BEGIN
          RETURN QUERY SELECT * FROM permissions WHERE permissions.service_id=service_uuid 
          AND permissions.perm_id LIKE CONCAT(service_uuid, '%');
    END $BODY$
    LANGUAGE plpgsql VOLATILE;

    -- Get new permissions from array with jsonb elements in time table
    CREATE OR REPLACE FUNCTION get_new_perms(perms jsonb)
      RETURNS TABLE(
        service_id uuid,
        perm_id character varying(256),
        actor_id uuid, perm_value smallint,
        default_value smallint,
        perm_type character varying(64),
        action_id character varying(256),
        description character varying(512),
        created timestamp,
        uuid uuid)
      RETURNS NULL ON NULL INPUT
    AS $BODY$
        BEGIN
          RETURN QUERY SELECT * FROM jsonb_populate_recordset(null::permissions, perms);
    END $BODY$
    LANGUAGE plpgsql VOLATILE;

    -- Delete permissions from table which exists in database and there is no in new permissions list
    CREATE OR REPLACE FUNCTION delete_old_permissions(service_id uuid, perms jsonb)
      RETURNS VOID
    AS $BODY$
      DECLARE
        service_uuid uuid;

      BEGIN
        service_uuid := service_id;
        IF EXISTS(SELECT * FROM get_old_perms(service_uuid)) THEN
          DELETE FROM permissions WHERE permissions.perm_id IN (SELECT DISTINCT(B.perm_id) 
          FROM get_new_perms(perms) AS A RIGHT JOIN get_old_perms(service_uuid) AS B ON A.perm_id = B.perm_id 
          WHERE A.perm_id IS NULL);

        END IF;
    END $BODY$ LANGUAGE plpgsql VOLATILE;
    """

    backwards_query = f"""
        DROP FUNCTION get_old_perms;
        DROP FUNCTION get_new_perms;
        DROP FUNCTION delete_old_permissions;
    """
