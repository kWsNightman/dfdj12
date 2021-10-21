import inspect
import json
import requests

from flask import current_app as app
from importlib import import_module
from urllib.parse import urljoin

from .base import BaseCommand
from ..ecdsa_lib import sign_data
from ..utils import check_if_auth_service
from ..utils import delete_old_permissions
from ..utils import json_dumps
from ..utils import get_auth_domain
from ..utils import get_language_header


class CollectPerms(BaseCommand):
    def run(self):
        # Get all required modules from actions folder.
        if not app.config.get('SERVICE_UUID'):
            print('Error. There is no SERVICE_UUID')
            return

        actions_path_files = self._get_path('actions')
        actions_files = dict()
        for path in actions_path_files:
            actions_files[path] = self._clean_and_sort(self._listdir_no_hidden(path))

        # Get all classes from actions modules.
        result = list()
        for path, actions in actions_files.items():
            path = path.replace('/', '.')
            for action in actions:
                mod_path = '{0}.{1}'.format(path, action[:-3])
                mod = import_module(mod_path)
                clsmembers = inspect.getmembers(mod, inspect.isclass)
                for class_tuple in clsmembers:
                    cls_parents = [c.__name__ for c in class_tuple[1].__bases__]
                    if 'BaseAction' not in cls_parents:
                        continue

                    class_obj = class_tuple[1]
                    permissions = class_obj.collect_all_perms()
                    for perm in permissions:
                        result.append({
                            'action_id': app.config['SERVICE_UUID'] + '/' + class_obj.__name__,
                            'default_value': perm.get('default_value'),
                            'description': perm.get('description'),
                            "perm_id": app.config['SERVICE_UUID'] + '/' + class_obj.__name__ + '/' +
                                       perm.get('perm_name'),
                            'perm_type': perm.get('perm_type'),
                            "service_id": app.config['SERVICE_UUID'],
                            "actor_id": None
                        })

        if result:
            delete_old_permissions(app.config['SERVICE_UUID'], result)

            if check_if_auth_service():
                self.__create_perms(result)
                print('Response status - 200 \nResponse content - Successfully created')
                return

            signature = sign_data(app.config['SERVICE_PRIVATE_KEY'], json_dumps(result, sort_keys=True))
            request_data = {
                "permissions": result,
                "signature": signature,
                "service_uuid": app.config['SERVICE_UUID']
            }
            response = requests.post(urljoin(get_auth_domain(), '/api/permissions/'), json=request_data,
                                     headers=get_language_header())
            try:
                content = response.json()
            except json.JSONDecodeError:
                print('Error with updating permissions on auth service')
                return

            if content.get('error'):
                print('Response status - %s \nResponse content - %s' % (response.status_code,
                                                                        content.get('error_message')))
            else:
                # Create default permissions
                self.__create_perms(content.get('permissions'))
                print('Response status - %s \nResponse content - %s' % (response.status_code, content.get('message')))
            return
        print('There is no permissions')

    @staticmethod
    def __create_perms(data):
        app.db.execute("""SELECT * FROM insert_or_update_perms(%s)""", [json_dumps(data)])