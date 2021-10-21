from . import base


class Migration(base.BaseMigration):
    """
    Create function to update/create actor from actors list of json
    """
    forwards_query = """
        DROP FUNCTION IF EXISTS get_received_actors CASCADE;
        -- Reformat array of actors in json to the table where column key is json key and column value is json value
        CREATE OR REPLACE FUNCTION get_received_actors(actors jsonb)
          RETURNS TABLE(
            uuid uuid,
            created timestamp,
            root_perms_signature text,
            initial_key character varying(130),
            secondary_keys jsonb,
            uinfo jsonb,
            actor_type character varying(64)
          )
          RETURNS NULL ON NULL INPUT
        AS $BODY$
            BEGIN
              RETURN QUERY SELECT * FROM jsonb_populate_recordset(null::actor, actors);
        END $BODY$
        LANGUAGE plpgsql VOLATILE;
        
        DROP FUNCTION IF EXISTS update_or_insert_actor_if_group_exists CASCADE;
        -- Main function that updates actors and create new one if one of actors group exists on service.
        CREATE OR REPLACE FUNCTION update_or_insert_actor_if_group_exists(actors jsonb)
          RETURNS VOID
        AS $BODY$
          DECLARE
            user_uuid uuid;
            user_secondary_keys jsonb;
            user_uinfo jsonb;
            user_root_perms_signature text;
            user_initial_key character varying(130);
            user_actor_type character varying(64);

          BEGIN
            FOR user_uuid, user_root_perms_signature, user_initial_key, user_secondary_keys, user_uinfo, user_actor_type in SELECT uuid, root_perms_signature, initial_key, secondary_keys, uinfo, actor_type FROM get_received_actors(actors) LOOP
              IF EXISTS(SELECT * FROM actor WHERE uuid = user_uuid) THEN
                UPDATE actor SET initial_key = COALESCE(user_initial_key, actor.initial_key),
                                 uinfo = COALESCE(actor.uinfo::jsonb, '{}'::jsonb) || user_uinfo,
                                 secondary_keys = COALESCE(actor.secondary_keys::jsonb, '{}'::jsonb) || user_secondary_keys,
                                 root_perms_signature = user_root_perms_signature
                WHERE actor.uuid = user_uuid;
              ELSE

                IF EXISTS(SELECT * FROM actor WHERE actor_type = 'group' AND uuid::text IN (SELECT jsonb_array_elements_text(user_uinfo->'groups'))) THEN

                  INSERT INTO actor(uuid, root_perms_signature, initial_key, secondary_keys, uinfo, actor_type) VALUES(user_uuid, user_root_perms_signature, user_initial_key, user_secondary_keys, user_uinfo, user_actor_type);
                end if;
              END IF;
            END LOOP;
        END $BODY$ LANGUAGE plpgsql VOLATILE;
        """

    backwards_query = f"""
        DROP FUNCTION get_received_actors;
        DROP FUNCTION update_actor;
    """
