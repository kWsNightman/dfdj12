import os

from flask_script import Command
from typing import Generator
from typing import List
from typing import Union


class BaseCommand(Command):
    """
    Base command for general functions
    """
    @staticmethod
    def _listdir_no_hidden(
            path: str
            ) -> Generator[str, None, None]:
        """
        The same as default os.listdir but returns
        no hidden files included in result list.
        """
        for f in os.listdir(path):
            if not f.startswith('.') and f.endswith('.py'):
                yield f

    @staticmethod
    def _clean_and_sort(
            files_list: Union[
                Generator[str, None, None],
                list
                ],
            actions: bool = False
            ) -> List[str]:
        """
        Remove unnecessary files and folders from
        migrations list and sort it in required order.
        """

        result_list = []
        for m in files_list:
            if m.endswith('.py'):
                result_list.append(m)
        try:
            result_list.remove('__init__.py')
        except ValueError:
            pass

        try:
            result_list.remove('base.py')
        except ValueError:
            pass

        if actions:
            try:
                result_list.remove('actions_setting.py')
            except ValueError:
                pass

        result_list.sort()
        return result_list

    @staticmethod
    def _get_path(folder_name: str) -> List[str]:
        """
        Walk over project dirictories to collect all received in params folders
        :param: folder_name - folder name what we looking for
        """

        files_paths = list()

        for root, dirs, files in os.walk("."):
            if folder_name in dirs:
                if root == '.':
                    files_paths.append(
                        root.lstrip('./') + folder_name)
                else:
                    files_paths.append(
                        root.lstrip('./') + '/' + folder_name)
        return files_paths