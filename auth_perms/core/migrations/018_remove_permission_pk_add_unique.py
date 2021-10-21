from . import base


class Migration(base.BaseMigration):
    """
    Remove PK constraint for permissions (perm_id, actor_id). Add unique index for creating one permission with
    actor set in NULL, add unique constraint
    """

    forwards_query = f"""
        DO $$ BEGIN
            ALTER TABLE permissions ALTER COLUMN actor_id DROP NOT NULL;
        EXCEPTION
            WHEN others THEN null;
        END $$;

        DO $$ BEGIN
            ALTER TABLE permissions ADD CONSTRAINT actor_id_perm_id_unique UNIQUE(perm_id, actor_id);
        EXCEPTION
            WHEN others THEN null;
        END $$;

        DO $$ BEGIN
            CREATE UNIQUE INDEX actor_id_null ON permissions (perm_id, (actor_id IS NULL)) WHERE actor_id IS NULL;
        EXCEPTION
            WHEN others THEN null;
        END $$;

        CREATE OR REPLACE FUNCTION insert_or_update_perms(IN perms jsonb)
        RETURNS SETOF permissions
        LANGUAGE  plpgsql VOLATILE
        RETURNS NULL ON NULL INPUT
        AS $$

          DECLARE
            permission RECORD;
            perm_uuid_list uuid[];
            perm_uuid uuid;
            updated_perm_uuid_list uuid[];

          BEGIN
            IF (jsonb_typeof(perms) = 'object') THEN
              perms := json_build_array(perms);
            END IF;
            FOR permission IN SELECT * FROM jsonb_populate_recordset(null::permissions, perms::jsonb) LOOP
                IF (permission.actor_id IS NULL) THEN
                    IF (SELECT EXISTS(SELECT 1 FROM permissions WHERE perm_id=permission.perm_id AND actor_id IS NULL)) THEN
                        WITH updated_perms AS(UPDATE permissions SET default_value=permission.default_value, perm_type=permission.perm_type, description=permission.description WHERE perm_id=permission.perm_id RETURNING uuid)
                        SELECT array_agg(uuid) FROM updated_perms INTO updated_perm_uuid_list;
                    ELSIF (permission.uuid IS NULL) THEN
                        INSERT INTO permissions(service_id, perm_id, actor_id, perm_value, default_value, perm_type, action_id, description, uuid) VALUES (permission.service_id, permission.perm_id, permission.actor_id, permission.perm_value, permission.default_value, permission.perm_type, permission.action_id, permission.description, DEFAULT) RETURNING uuid INTO perm_uuid;
                    ELSE
                        INSERT INTO permissions(service_id, perm_id, actor_id, perm_value, default_value, perm_type, action_id, description, uuid) VALUES (permission.service_id, permission.perm_id, permission.actor_id, permission.perm_value, permission.default_value, permission.perm_type, permission.action_id, permission.description, permission.uuid) RETURNING uuid INTO perm_uuid;
                    END IF;
                ELSE
                    IF (SELECT EXISTS(SELECT 1 FROM permissions WHERE perm_id=permission.perm_id AND actor_id=permission.actor_id)) THEN
                        UPDATE permissions SET perm_value=permission.perm_value, default_value=permission.default_value, perm_type=permission.perm_type, description=permission.description WHERE perm_id=permission.perm_id AND actor_id=permission.actor_id RETURNING uuid INTO perm_uuid;
                    ELSIF (permission.uuid IS NULL) THEN
                        INSERT INTO permissions(service_id, perm_id, actor_id, perm_value, default_value, perm_type, action_id, description, uuid) VALUES (permission.service_id, permission.perm_id, permission.actor_id, permission.perm_value, permission.default_value, permission.perm_type, permission.action_id, permission.description, DEFAULT) RETURNING uuid INTO perm_uuid;
                    ELSE
                        INSERT INTO permissions(service_id, perm_id, actor_id, perm_value, default_value, perm_type, action_id, description, uuid) VALUES (permission.service_id, permission.perm_id, permission.actor_id, permission.perm_value, permission.default_value, permission.perm_type, permission.action_id, permission.description, permission.uuid) RETURNING uuid INTO perm_uuid;
                    END IF;
                END IF;

                IF (perm_uuid IS NOT NULL) THEN
                    perm_uuid_list := array_append(perm_uuid_list, perm_uuid);
                ELSIF (updated_perm_uuid_list IS NOT NULL) THEN
                    perm_uuid_list := perm_uuid_list || updated_perm_uuid_list;
                END IF;
                perm_uuid := NULL;
                updated_perm_uuid_list := NULL;
            END LOOP;
            RETURN QUERY SELECT * FROM permissions WHERE uuid = ANY(perm_uuid_list);
          END $$;

        UPDATE permissions SET actor_id = NULL WHERE perm_value IS NULL;
        """

    backwards_query = f""""""
