from . import base


class Migration(base.BaseMigration):
    """
    SET actor_id into NULL for old permissions where actor_id was service_id
    """

    forwards_query = f"""
        DO $$
        BEGIN
            IF NOT (SELECT EXISTS(SELECT 1 FROM permissions WHERE perm_value IS NULL AND actor_id is NULL)) THEN
                UPDATE permissions SET actor_id=NULL WHERE perm_value IS NULL;
            END IF;
        END $$;
        """

    backwards_query = f""""""
