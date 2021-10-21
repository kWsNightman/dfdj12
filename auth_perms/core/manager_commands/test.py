import os
import sys
import importlib
import inspect
import typing as ty

from flask_script import Command, Option

from ..base_test import BaseTest


class RunTests(Command):
    """
    Run tests
    """

    option_list = (
        Option('--directory', '-d', dest='directory', default=os.getcwd(), required=False,
               help='Directory with tests. By default current working directory'),
        Option('--recursive', '-r', dest='recursive', action="store_true", default=False, required=False,
               help='Specify this option if you want to search for tests in subdirectories')
    )

    def run(self, directory: str, recursive: bool):
        if not os.path.exists(directory):
            print(f'ERROR! Path {directory} does not exist!')
            return

        modules = self.get_modules(directory, recursive)

        if not modules:
            print(f'ERROR! Not found python modules in directory {directory}')
            return

        base_test_inheritors = list()

        for module_path in modules:
            classes = self.get_module_classes(module_path)

            base_test_inheritors.extend(
                [cls for _, cls in classes if issubclass(cls, BaseTest)]
            )

        if not base_test_inheritors:
            print(f'ERROR! Not found child classes for BaseTest class in directory {directory}')
            return

        for cls in base_test_inheritors:
            cls().run()

    @staticmethod
    def get_modules(directory: str, recursive: bool) -> ty.List[str]:
        modules = list()

        files_and_dirs = os.listdir(directory)

        for entry in files_and_dirs:
            full_path = os.path.join(directory, entry)

            if recursive and os.path.isdir(full_path):
                modules.extend(RunTests.get_modules(full_path, recursive))
            elif full_path.endswith('.py'):
                modules.append(full_path)

        return modules

    @staticmethod
    def get_module_classes(module_path: str) -> ty.List[ty.Tuple[str, ty.Any]]:
        module = importlib.import_module(os.path.relpath(module_path).replace('.py', '').replace('/', '.'))

        classes = inspect.getmembers(module, inspect.isclass)
        return classes
