from . import base


class Migration(base.BaseMigration):
    """
    Create permissions table.
    """
    forwards_query = f"""
        CREATE OR REPLACE FUNCTION get_actor_groups(actor_uuid uuid) RETURNS SETOF uuid
        RETURNS NULL ON NULL INPUT
        LANGUAGE  plpgsql VOLATILE
        AS $$
        BEGIN

            RETURN QUERY SELECT uuid FROM actor WHERE uuid IN (
                SELECT elements::uuid FROM actor, jsonb_array_elements_text(uinfo -> 'groups') elements WHERE uuid = actor_uuid)
            ORDER BY (uinfo->>'weight')::bigint DESC;

        END$$;
        """

    backwards_query = f"""
        DROP FUNCTION get_actor_groups;
    """
