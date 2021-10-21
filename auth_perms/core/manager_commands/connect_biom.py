import subprocess

from flask_script import Command
from flask import current_app as app

from ..service_view import GetAndUpdateGroups
from ..utils import json_dumps


class ConnectBiom(Command):
    """
    Connect you service to biom with auth credentials from local_settings.py
    """

    def run(self, *args, **kwargs):

        if app.config.get('AUTH_STANDALONE') is True:
            print('\033[91mYou can\'t use this command with AUTH_STANDALONE = True\033[0m')
            return

        auth_uuid = app.config.get('AUTH_UUID')
        biom_name = app.config.get('BIOM_NAME')
        auth_pub_key = app.config.get('AUTH_PUB_KEY')
        auth_domain = app.config.get('AUTH_DOMAIN')

        if not auth_uuid or not biom_name or not auth_pub_key or not auth_domain:
            print(f'\033[93mNot all auth credentials in local_settings.py\n'
                  f'AUTH_UUID = {auth_uuid}\n'
                  f'BIOM_NAME = {biom_name}\n'
                  f'AUTH_PUB_KEY = {auth_pub_key}\n'
                  f'AUTH_DOMAIN = {auth_domain}\033[0m')
            return

        service_uuid = app.config.get('SERVICE_UUID')
        service_public_key = app.config.get('SERVICE_PUBLIC_KEY')
        service_domain = app.config.get('SERVICE_DOMAIN')
        service_name = app.config.get('SERVICE_NAME')

        if not service_uuid or not service_public_key or not service_domain or not service_name:
            print(f'\033[93mNot all your service credentials on local_settings.py\n'
                  f'SERVICE_UUID = {service_uuid}\n'
                  f'SERVICE_PUBLIC_KEY = {service_public_key}\n'
                  f'SERVICE_DOMAIN = {service_domain}\n'
                  f'SERVICE_NAME = {service_name}\033[0m')
            return

        db = app.config.get('DATABASE')

        subprocess.call('pg_dump postgresql://{USER}:{PASSWORD}@{HOST}:{PORT}/{NAME} > ~/standalone_dump.sql'
                        .format(**db), shell=True)
        app.db.execute("""TRUNCATE actor CASCADE""")

        biom = {'initial_key': auth_pub_key, 'actor_type': 'service',
                'uinfo': {'service_name': 'auth', 'service_domain': auth_domain, 'biom_name': biom_name},
                'uuid': auth_uuid}

        service = {'initial_key': service_public_key, 'actor_type': 'service',
                   'uinfo': {'service_name': service_name, 'service_domain': service_domain, 'description': ''},
                   'uuid': service_uuid}

        values = [json_dumps([service, biom])]

        query = """INSERT INTO actor (SELECT * FROM jsonb_populate_recordset(null::actor, jsonb %s))
                   RETURNING uuid, uinfo"""
        try:
            app.db.fetchone(query, values)
        except Exception as e:
            print(f'\033[91m{e}\033[0m')
            return

        try:
            groups = GetAndUpdateGroups().update_groups()
        except Exception:
            app.db.execute("""TRUNCATE actor CASCADE""")
            subprocess.call('psql postgresql://{USER}:{PASSWORD}@{HOST}:{PORT}/{NAME} < ~/standalone_dump.sql'
                            .format(**db), shell=True, stderr=subprocess.STDOUT, stdout=subprocess.DEVNULL)
            print('\033[91mError with getting default groups. Check that your service is registered on auth and'
                  ' have the necessary permissions for getting groups\033[0m')
            return

        if groups is None:
            app.db.execute("""TRUNCATE actor CASCADE""")
            subprocess.call('psql postgresql://{USER}:{PASSWORD}@{HOST}:{PORT}/{NAME} < ~/standalone_dump.sql'
                            .format(**db), shell=True, stderr=subprocess.STDOUT, stdout=subprocess.DEVNULL)
            print('\033[91mError with getting default groups. Check that your service is registered on auth and'
                  ' have the necessary permissions for getting groups\033[0m')
            return

        print(f'\033[92mSuccessfully connected to biom\033[0m')
        return
