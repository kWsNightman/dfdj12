import os
import uuid
from getpass import getpass

from flask_script import Command
from flask_script import Option
from flask import current_app as app

from email_validator import EmailNotValidError
from email_validator import validate_email as email_validator_function

from ..ecdsa_lib import sign_data
from ..ecdsa_lib import generate_key_pair
from ..utils import hash_md5
from ..utils import json_dumps
from ..utils import get_default_user_group


class CreateRootUser(Command):
    """
    Create root user for standalone mode
    """

    option_list = (
        Option('--first_name', '-fn', dest='first_name'),
        Option('--last_name', '-ln', dest='last_name'),
        Option('--email', '-e', dest='email'),
        Option('--password', '-p', dest='password'),
    )

    def run(self, first_name=None, last_name=None, email=None, password=None):

        if not self.__check_table_exists():
            print('\033[93mBefore creating root user, you should apply migrations.\033[0m')
            return

        if not os.getuid() == 0:
            print('\033[93mYou should use this command from root only!\033[0m')
            return

        if first_name is None:
            first_name = input('First Name:')
        if last_name is None:
            last_name = input('Last Name:')
        if email is None:
            email = input('Email address:')

        try:
            email_validator_function(email)
        except EmailNotValidError as e:
            print(f'\033[91m{str(e)}\033[0m')
            return

        if app.db.fetchone("""SELECT EXISTS(SELECT 1 FROM actor WHERE uinfo ->> 'email' = %s)""",
                           [email]).get('exists'):
            print('\033[91mUser with such email already exists.\033[0m')
            return

        if password is None:
            password = getpass('Password:')
            password_confirm = getpass('Password confirm:')

            if password != password_confirm:
                print('\033[91mPasswords didn\'t match.\033[0m')
                return

        uinfo = {'email': email, 'groups': [get_default_user_group().get('uuid')],
                 'password': hash_md5(password), 'last_name': last_name, 'first_name': first_name}

        root_uuid = uuid.uuid4()
        private_key, public_key = generate_key_pair()
        root_signature = sign_data(app.config['SERVICE_PRIVATE_KEY'], root_uuid.__str__() + public_key)

        actor = {'initial_key': public_key, 'root_perms_signature': root_signature,
                 'actor_type': 'classic_user', 'uinfo': uinfo, 'uuid': root_uuid}

        values = [json_dumps(actor)]
        query = """INSERT INTO actor (SELECT * FROM jsonb_populate_record(null::actor, jsonb %s)) RETURNING uuid"""

        try:
            actor_uuid = app.db.fetchone(query, values)
        except Exception as e:
            print(f'\033[91m{e}\033[0m')
            return

        print(f'\033[92mRoot user {actor_uuid.get("uuid")} successfully created.\033[0m')
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
