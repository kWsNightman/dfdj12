from uuid import uuid4

from flask_script import Command
from flask_script import Option
from flask import current_app as app

from ..ecdsa_lib import generate_key_pair
from ..utils import json_dumps


class CreateService(Command):
    """
    If AUTH_STANDALONE = True - create service actor and default groups in database
    If AUTH_STANDALONE = False - create only service actor in database
    """

    option_list = (
        Option('--service_name', '-sn', dest='service_name'),
        Option('--service_domain', '-sd', dest='service_domain'),
        Option('--description', '-dn', dest='description'),
        Option('--deploy', '-d', dest='deploy', action='store_true')
    )

    def run(self, service_name=None, service_domain=None, description=None, deploy: bool = False):

        if not self.__check_table_exists():
            print('\033[93mBefore creating service, you should apply migrations\033[0m')
            return

        if service_name is None:
            service_name = input('Service name:')
        if service_domain is None:
            service_domain = input('Service domain:')
        if description is None:
            description = input('Description:')

        if app.db.fetchone("""SELECT EXISTS (SELECT 1 FROM actor WHERE actor_type = 'group'
                              AND uinfo ->> 'group_name' in ('BAN', 'ADMIN', 'DEFAULT'))""").get('exists'):
            print('\033[91mOne of the default groups already exists.\033[0m')
            return

        private_key, public_key = generate_key_pair()
        uinfo = {'service_name': service_name, 'service_domain': service_domain, 'description': description}
        actor = {'initial_key': public_key, 'actor_type': 'service', 'uinfo': uinfo, 'uuid': uuid4()}

        values = [actor]

        default = {'actor_type': 'group', 'uinfo': {'weight': 0, 'group_name': 'DEFAULT'}, 'uuid': uuid4()}
        admin = {'actor_type': 'group', 'uinfo': {'weight': 4294967298, 'group_name': 'ADMIN'}, 'uuid': uuid4()}
        ban = {'actor_type': 'group', 'uinfo': {'weight': 4294967299, 'group_name': 'BAN'}, 'uuid': uuid4()}

        if app.config.get('AUTH_STANDALONE'):
            values.extend([default, admin, ban])

        query = """INSERT INTO actor (SELECT * FROM jsonb_populate_recordset(null::actor, jsonb %s))
                   RETURNING uuid, uinfo"""
        try:
            actor_uuid = app.db.fetchone(query, [json_dumps(values)])
        except Exception as e:
            print(f'\033[91m{e}\033[0m')
            return
        if deploy:
            print(f'SERVICE_UUID = "{actor_uuid.get("uuid")}"\n'
                  f'SERVICE_PUBLIC_KEY = "{public_key}"\n'
                  f'SERVICE_PRIVATE_KEY = "{private_key}"\n'
                  f'SERVICE_DOMAIN = "{actor_uuid.get("uinfo")["service_domain"]}"\n'
                  f'SERVICE_NAME = "{actor_uuid.get("uinfo")["service_name"]}"')

        else:
            print(f'\033[92mService successfully created. Paste this data to local_setting.py\n'
                  f'SERVICE_UUID = "{actor_uuid.get("uuid")}"\n'
                  f'SERVICE_PUBLIC_KEY = "{public_key}"\n'
                  f'SERVICE_PRIVATE_KEY = "{private_key}"\n'
                  f'SERVICE_DOMAIN = "{actor_uuid.get("uinfo")["service_domain"]}"\n'
                  f'SERVICE_NAME = "{actor_uuid.get("uinfo")["service_name"]}"\033[0m')
        return

    @staticmethod
    def __check_table_exists():
        table_name = f'actor'
        with app.db.get_cursor() as cur:
            cur.execute('SELECT COUNT(*) FROM information_schema.tables '
                        'WHERE table_name=%s', (table_name,))
            result = cur.fetchone()

        if result.get('count', None) == 1:
            return True
        return False
