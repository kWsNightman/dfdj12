from . import base


class Migration(base.BaseMigration):
    """
    Create permissions table.
    """
    forwards_query = f"""

        -- Getting list of permissions for an action
        CREATE OR REPLACE FUNCTION get_list_perm_ids(action character, permission_type character) RETURNS SETOF varchar
        LANGUAGE  plpgsql VOLATILE
        RETURNS NULL ON NULL INPUT
        
        AS $$
          BEGIN
        
            RETURN QUERY SELECT DISTINCT(perm_id) FROM permissions WHERE action_id = action AND 
                                                                         perm_type=permission_type;
        
          END $$;
        
        
        -- Getting permission value
        CREATE OR REPLACE FUNCTION get_biom_perm_value(actor uuid, permission_id varchar, groups uuid[]) RETURNS INTEGER
        LANGUAGE  plpgsql VOLATILE
        RETURNS NULL ON NULL INPUT
        AS $$
        
          DECLARE
            group_uuid uuid;
            result     smallint;
        
          BEGIN
        
              IF EXISTS(SELECT * FROM permissions WHERE actor_id=actor AND perm_id=permission_id) THEN
        
                SELECT INTO result perm_value FROM permissions WHERE actor_id=actor AND perm_id=permission_id;
                RETURN result;
        
              ELSEIF array_length(groups, 1) > 0 THEN
        
                FOREACH group_uuid IN ARRAY groups LOOP
        
                  IF EXISTS(SELECT * FROM permissions WHERE actor_id=group_uuid AND perm_id=permission_id) THEN
        
                    SELECT INTO result perm_value FROM permissions WHERE actor_id=group_uuid AND perm_id=permission_id;
                    RETURN result;
        
                  END IF;
        
                END LOOP;
        
              END IF;
        
              SELECT INTO result default_value FROM permissions WHERE perm_id=permission_id AND perm_value IS NULL;
              RETURN result;
        
          END $$;
        
        
        -- Getting biom permission ids with values
        CREATE OR REPLACE FUNCTION get_biom_permissions(actor uuid, action character, permission_type character)
        RETURNS TABLE(
          permission_id     varchar,
          value             smallint
        )
        LANGUAGE  plpgsql VOLATILE
        RETURNS NULL ON NULL INPUT
        AS $$
        
          DECLARE
            groups uuid[];
            perm_id varchar;
        
          BEGIN
        
            groups := ARRAY(SELECT get_actor_groups(actor));
        
            FOR perm_id IN SELECT * FROM get_list_perm_ids(action, permission_type) LOOP
        
              permission_id := perm_id;
              value := get_biom_perm_value(actor, perm_id, groups);
              RETURN NEXT;
        
            END LOOP;
        
          END $$;

        """

    backwards_query = f"""
        DROP FUNCTION get_list_perm_ids;
        DROP FUNCTION get_biom_perm_value;
        DROP FUNCTION get_biom_permissions;
    """
