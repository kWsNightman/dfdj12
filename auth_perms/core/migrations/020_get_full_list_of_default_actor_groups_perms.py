from . import base


class Migration(base.BaseMigration):
    """
    Create functions which collects all default permissions, actor permissions, group permissions for standalone mode
    """
    forwards_query = """
        DROP FUNCTION IF EXISTS collect_full_list_of_actor_perms CASCADE;
        
        CREATE OR REPLACE FUNCTION collect_full_list_of_actor_perms(actor_uuid uuid, OUT result jsonb)
            RETURNS jsonb
            LANGUAGE plpgsql
            STRICT
        AS $function$
        BEGIN
            SELECT jsonb_agg(jsonb_build_object('uuid', P.uuid, 'perm_id', P.perm_id, 'action_id', 
            P.action_id, 'actor_id', P.actor_id, 'service_id', P.service_id, 'created', P.created, 
            'perm_type', P.perm_type, 'perm_value', P.perm_value, 'default_value', P.default_value, 
            'description', P.description)) INTO result FROM permissions AS P 
            WHERE P.actor_id=actor_uuid AND perm_value IS NOT NULL;
        END $function$;

        DROP FUNCTION IF EXISTS collect_full_list_of_groups_perms CASCADE;
        
        CREATE OR REPLACE FUNCTION collect_full_list_of_groups_perms(actor uuid, OUT result jsonb)
            RETURNS jsonb
            LANGUAGE plpgsql
            STRICT
        AS $function$
        BEGIN
            SELECT jsonb_object_agg(actor_id, g) FROM (SELECT jsonb_agg(jsonb_build_object('uuid', P.uuid, 'perm_id', 
            P.perm_id, 'action_id', P.action_id, 'actor_id', P.actor_id, 'service_id', P.service_id, 'created', 
            P.created, 'perm_type', P.perm_type, 'perm_value', P.perm_value, 'default_value', 
            P.default_value, 'description', P.description))g, actor_id FROM permissions AS P where
            P.actor_id IN (SELECT groups::uuid FROM actor AS A,
            jsonb_array_elements_text(A.uinfo->'groups')
            groups WHERE A.uuid=actor) AND perm_value IS NOT NULL GROUP BY P.actor_id)s INTO result;
        END $function$;
    
        DROP FUNCTION IF EXISTS collect_full_list_of_default_perms CASCADE;

        CREATE OR REPLACE FUNCTION public.collect_full_list_of_default_perms(actor uuid, OUT result jsonb)
            RETURNS jsonb
            LANGUAGE plpgsql
            STRICT
        AS $function$
        BEGIN
            SELECT jsonb_agg(jsonb_build_object('uuid', P.uuid, 'perm_id', P.perm_id, 'action_id', P.action_id, 
            'actor_id', P.actor_id, 'service_id', P.service_id, 'created', P.created, 'perm_type', P.perm_type, 
            'perm_value', P.perm_value, 'default_value', P.default_value, 'description', P.description)) INTO result 
            FROM permissions AS P WHERE perm_value IS NULL AND P.action_id NOT IN (SELECT
            action_id FROM permissions where actor_id=actor);
        END $function$;

        DROP FUNCTION IF EXISTS collect_full_list_of_compiled_actor_perms CASCADE;
        
        
        CREATE OR REPLACE FUNCTION public.collect_full_list_of_compiled_actor_perms(actor_uuid uuid, OUT result jsonb)
            RETURNS jsonb
            LANGUAGE plpgsql
            STRICT
        AS $function$
        BEGIN
            WITH default_perms AS (
                SELECT * FROM permissions WHERE perm_value IS NULL
            ),
            user_perms AS (
                SELECT * FROM permissions WHERE actor_id=actor_uuid
            ),
            group_perms AS (
                SELECT * FROM permissions WHERE uuid IN (SELECT DISTINCT ON (perm_id) permissions.uuid FROM permissions
                JOIN actor ON permissions.actor_id = actor.uuid WHERE actor.uuid IN (select 
                (jsonb_array_elements_text(uinfo->'groups'))::uuid FROM actor WHERE uuid = actor_uuid)
                ORDER BY perm_id, (uinfo->'weight')::bigint DESC)
            ),
            priority_perms(permissions) AS (
                SELECT jsonb_agg(jsonb_build_object(
                'uuid', COALESCE(A.uuid, G.uuid, D.uuid), 
                'perm_id', COALESCE(A.perm_id, G.perm_id, D.perm_id), 
                'action_id', COALESCE(A.action_id, G.action_id, D.action_id), 
                'actor_id', COALESCE(A.actor_id, G.actor_id, D.actor_id),  
                'service_id', COALESCE(A.service_id, G.service_id, D.service_id), 
                'created', COALESCE(A.created, G.created, D.created), 
                'perm_type', COALESCE(A.perm_type, G.perm_type, D.perm_type),
                'perm_value', COALESCE(A.perm_value, G.perm_value, D.perm_value), 
                'default_value', COALESCE(A.default_value, G.default_value, D.default_value), 
                'description', COALESCE(A.description, G.description, D.description))) 
                FROM default_perms AS D LEFT JOIN group_perms AS G ON D.perm_id = G.perm_id 
                LEFT JOIN user_perms AS A ON D.perm_id = A.perm_id
            ),
            not_priority_perms AS (
                SELECT jsonb_agg(jsonb_build_object(
                'uuid', uuid, 'perm_id', perm_id, 'action_id', action_id, 'actor_id', actor_id,
                'service_id', service_id, 'created', created, 'perm_type', perm_type, 
                'perm_value', perm_value, 'default_value', default_value, 'description', description))
                FROM permissions WHERE uuid NOT IN (SELECT jsonb_array_elements_text(
                (SELECT jsonb_agg(uuids->'uuid') FROM (SELECT jsonb_array_elements(permissions) AS uuids
                FROM priority_perms)s))::uuid) AND actor_id IN (SELECT 
                (jsonb_array_elements_text(uinfo->'groups'))::uuid FROM actor WHERE uuid = actor_uuid)
            )
            SELECT jsonb_build_object('priority', (SELECT * FROM priority_perms),
            'not_priority', (SELECT * FROM not_priority_perms)) INTO result;
        END $function$;
        
        DROP FUNCTION IF EXISTS collect_full_list_of_default_actor_groups_perms CASCADE;
        
        CREATE OR REPLACE FUNCTION public.collect_full_list_of_default_actor_groups_perms(actor uuid)
            RETURNS TABLE(result jsonb)
            LANGUAGE plpgsql
            STRICT
        AS $function$
        BEGIN
            RETURN QUERY SELECT jsonb_build_object('default', 
            collect_full_list_of_default_perms(actor), 'actor', collect_full_list_of_actor_perms(actor), 
            'groups', collect_full_list_of_groups_perms(actor), 'compiled', 
            collect_full_list_of_compiled_actor_perms(actor));
        END $function$;
        """

    backwards_query = f"""
        DROP FUNCTION collect_full_list_of_actor_perms;
        DROP FUNCTION collect_full_list_of_groups_perms;
        DROP FUNCTION collect_full_list_of_default_perms;
        DROP FUNCTION collect_full_list_of_compiled_actor_perms;
        DROP FUNCTION collect_full_list_of_default_actor_groups_perms;
    """
