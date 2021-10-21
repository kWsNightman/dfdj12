import inspect
import os

from .base import BaseCommand
from importlib import import_module

from ..utils import json_dumps


class CollectActions(BaseCommand):
    """
    Run to write all names of action classes info into
    actions/actions_setting.py file
    """
    ACTIONS_SETTINGS = 'actions/actions_settings.py'

    def run(self) -> None:
        actions_settings_path = os.path.join(
            os.path.dirname(os.path.abspath(os.path.join(__file__, '../..'))),
            self.ACTIONS_SETTINGS
        )

        actions_files_path = self._get_path('actions')
        actions_files = dict()
        for path in actions_files_path:
            actions_files[path] = self._clean_and_sort(self._listdir_no_hidden(path))

        actions_list = dict()
        for path, files in actions_files.items():
            path = path.replace('/', '.')
            for file in files:
                mod_path = '{}.{}'.format(path, file[:-3])
                mod = import_module(mod_path)
                clsmembers = inspect.getmembers(mod, inspect.isclass)

                for class_tuple in clsmembers:
                    cls_parents = [c.__name__ for c in class_tuple[1].__bases__]
                    if 'BaseAction' not in cls_parents:
                        continue

                    if path not in actions_list:
                        actions_list[path] = list()
                    actions_list[path].append(class_tuple)

        # Convert class paths appropriate to Flask environment.
        result_list = []

        for path, actions in actions_list.items():
            for action in actions:
                module = '{0}.{1}'.format(
                    path, action[0])

                result_list.append(module)

        def write_actions(f, result) -> None:
            # Write result to a file.
            f.write('DEFINED_ACTIONS = ')
            f.write(json_dumps(result, indent=4))
            f.write('\n')

        if 'actions' not in os.listdir('.'):
            os.mkdir(os.path.abspath(os.path.join('.', 'actions')))

        if not os.path.isfile(actions_settings_path):
            # Create actions/actions_settings.py file and
            # write path list to it.
            with open(actions_settings_path, 'w+') as f:
                write_actions(f, sorted(result_list))
        else:
            # Read actions/actions_settings.py file and
            # replace or add path list to it.
            with open(actions_settings_path, 'r+') as f:
                lines = f.readlines()
                f.seek(0)
                start_line = None
                for i, line in enumerate(lines):
                    if 'DEFINED_ACTIONS' in line:
                        start_line = i
                    if ']' in line and start_line is not None:
                        lines[i] = ''
                        break
                    if start_line is not None:
                        lines[i] = ''
                f.writelines(lines)
                f.truncate()
                write_actions(f, sorted(result_list))

        print('Successfully collected.')
