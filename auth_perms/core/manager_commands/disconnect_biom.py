import subprocess

from uuid import uuid4
from flask import current_app as app
from flask_script import Command
from flask_script import Option

from ..utils import json_dumps


class DisconnectBiom(Command):
    """
    Disconnect you service from biom
    """

    option_list = (
        Option('--dump', '-d', dest='dump'),
    )

    def run(self, dump=None):

        if app.config.get('AUTH_STANDALONE') is False:
            print('\033[91mYou can\'t use this command with AUTH_STANDALONE = False\033[0m')
            return

        if dump:
            db = app.config.get('DATABASE')
            app.db.execute("""TRUNCATE actor CASCADE""")
            subprocess.call('psql postgresql://{USER}:{PASSWORD}@{HOST}:{PORT}/{NAME} < {dump}'.format(**db, dump=dump),
                            shell=True, stderr=subprocess.STDOUT, stdout=subprocess.DEVNULL)
            print(f'\033[92mSuccessfully disconnected from biom with restore db from dump.\033[0m')
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

        app.db.execute("""TRUNCATE actor CASCADE""")

        service = {'initial_key': service_public_key, 'actor_type': 'service',
                   'uinfo': {'service_name': service_name, 'service_domain': service_domain, 'description': ''},
                   'uuid': service_uuid}

        default = {'actor_type': 'group', 'uinfo': {'weight': 0, 'group_name': 'DEFAULT'}, 'uuid': uuid4()}
        admin = {'actor_type': 'group', 'uinfo': {'weight': 4294967298, 'group_name': 'ADMIN'}, 'uuid': uuid4()}
        ban = {'actor_type': 'group', 'uinfo': {'weight': 4294967299, 'group_name': 'BAN'}, 'uuid': uuid4()}

        values = [json_dumps([service, default, admin, ban])]

        query = """INSERT INTO actor (SELECT * FROM jsonb_populate_recordset(null::actor, jsonb %s))
                   RETURNING uuid, uinfo"""
        try:
            app.db.fetchone(query, values)
        except Exception as e:
            print(f'\033[91m{e}\033[0m')
            return

        print(f'\033[92mSuccessfully disconnected from biom\033[0m')
        return
