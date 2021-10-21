import inspect
import os

from flask import current_app as app
from flask_script import Command
from flask_script import Option
from importlib import import_module
from psycopg2.errors import DuplicateTable
from typing import Generator
from typing import List
from typing import Optional
from typing import Union

from ..migrations.base import backward_migration
from ..migrations.base import forward_migration


class MigrateBase(Command):
    """
    Base class for migrate commands.
    """
    option_list = (
        Option('--name', '-n', dest='name'),
    )

    @staticmethod
    def __listdir_no_hidden(
            path: str
            ) -> Generator[str, None, None]:
        """
        The same as default os.listdir but returns
        no hidden files included in result list.
        """
        for f in os.listdir(path):
            if not f.startswith('.'):
                yield f

    def _get_migrations_list(self) -> List[dict]:
        """
        Get list of migration files from migrations/ folder.
        """
        migrations_paths = self._get_migrations_paths()

        migrations_list = list()
        main_migrations_list = list()
        for path in migrations_paths:
            if path.endswith('auth_perms/core/migrations'):
                main_migrations_list = self._clean_and_sort(
                    self.__listdir_no_hidden(path))
                main_migrations_list = self._form_migration_dicts(
                    main_migrations_list, path)
            else:
                raw_migrations_list = self._clean_and_sort(
                    self.__listdir_no_hidden(path))
                migrations_list += self._form_migration_dicts(
                    raw_migrations_list, path)

        return main_migrations_list + migrations_list

    @staticmethod
    def _form_migration_dicts(
            migrations_list: List[str],
            folder_path: str
        ) -> List[dict]:
        """
        Form migrations list of dictionaries with import path
        and name as it will be presented in migrations database
        table.
        """
        result = []
        folder_path = folder_path.replace('/', '.')
        for name in migrations_list:
            migration = {
                'name': name,
                'path': f'{folder_path}.{name}'
            }
            result.append(migration)
        return result

    @staticmethod
    def _clean_and_sort(
            migrations_list: Union[
                Generator[str, None, None],
                list
                ]
            ) -> List[str]:
        """
        Remove unnecessary files and folders from
        migrations list and sort it in required order.
        """
        result_list = []
        for m in migrations_list:
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

        result_list = [r[:-3] for r in result_list]
        result_list.sort()
        return result_list

    @staticmethod
    def _get_migrations_paths() -> List[str]:
        """
        Walk over project dirictories to collect all
        /migrations folders.
        """
        migrations_paths = list()
        for root, dirs, files in os.walk("."):
            if 'migrations' in dirs:
                if root == '.':
                    migrations_paths.append(
                        root.lstrip('./') + 'migrations')
                else:
                    migrations_paths.append(
                        root.lstrip('./') + '/migrations')
        return migrations_paths

    @staticmethod
    def _get_migration_module(path: str):
        """
        Get and return migration module.
        """
        return import_module(path)


class MigrateForwards(MigrateBase):
    """
    Run forward all migrations or particular one from
    migrations/ folder.
    """
    def run(self, name: Optional[str] = None) -> None:
        self.__create_migrations_table()

        list_of_migrations = self._get_migrations_list()

        if not name:
            for migration in list_of_migrations:
                self.apply_forward_migration(migration)
            print('Successfully applied.')
        else:
            applied = False
            for migration in list_of_migrations:
                if name == migration['name']:
                    self.apply_forward_migration(migration)
                    applied = True
                    print('Successfully applied.')
                    break
            if not applied:
                print(f'Migration {name} not found.')

    def apply_forward_migration(self, migration: dict) -> None:
        """
        Forward migration by given dict with path and name of
        migration.
        """
        try:
            mod = self._get_migration_module(migration['path'])
        except Exception as e:
            print('-' * 20, 'ERROR', '-' * 20)
            print('Migration can not be applied! Module import error - %s! Migration name - %s, migration path - %s' %
                  (e, migration.get('name', ''), migration.get('path', '')))
            print('-' * 45)
            return

        if not hasattr(mod, 'Migration'):
            print('-' * 20, 'ERROR', '-' * 20)
            print('Migration has no class Migration! Migration name - %s, migration path - %s' %
                  (migration.get('name', ''), migration.get('path', '')))
            print('-' * 45)
            return

        if not inspect.isclass(mod.Migration):
            print('-' * 20, 'ERROR', '-' * 20)
            print('Migration is not a class! Migration name - %s, migration path - %s' %
                  (migration.get('name', ''), migration.get('path', '')))
            print('-' * 45)
            return

        cls_parents = [c.__name__ for c in mod.Migration.__bases__]
        if 'BaseMigration' not in cls_parents:
            print('-' * 20, 'ERROR', '-' * 20)
            print('Migration has no parent BaseMigration! Migration name - %s, migration path - %s' %
                  (migration.get('name', ''), migration.get('path', '')))
            print('-' * 45)
            return

        if not hasattr(mod.Migration, 'forwards_query'):
            print('-' * 20, 'ERROR', '-' * 20)
            print('Migration has no forwards_query! Migration name - %s, migration path - %s' %
                  (migration.get('name', ''), migration.get('path', '')))
            print('-' * 45)
            return

        forward_migration(
            mod.Migration(),
            mod.Migration.table_name,
            migration['name']
        )

    @staticmethod
    def __create_migrations_table() -> None:
        """
        Create table to store migrations history.
        """
        query = f"""
            CREATE TABLE migrations (
                id SERIAL,
                name character varying(255) NOT NULL,
                file_name character varying(255) NOT NULL UNIQUE,
                applied timestamp with time zone DEFAULT now()
            )
            """
        try:
            with app.db.get_cursor() as cur:
                cur.execute(query)
        except DuplicateTable:
            pass


class MigrateBackwards(MigrateBase):
    """
    Run backward particular migration by given name.
    """
    def run(self, name: str = None) -> None:
        if not name:
            print('-n or --name option is required.')
            return

        if self.__verify_migration_existence(name):
            list_of_migrations = self._get_migrations_list()
            migration_names = [n['name'] for n in list_of_migrations]
            if name in migration_names:
                list_index = migration_names.index(name)
                path = list_of_migrations[list_index]['path']
                mod = import_module(path)
                f_names_list = self.__get_further_migrations(name)
                f_names_list = [n['file_name'] for n in f_names_list]
                f_names_list.reverse()

                further_migrations = []
                for f_name in f_names_list:
                    for migration in list_of_migrations:
                        if f_name == migration['name']:
                            further_migrations.append(migration)
                            break

                ask = input((
                    'Following migrations also will be reverted: '
                    f'{f_names_list} Continue?[Y/n]'))

                if ask in ('Y', 'y', 'yes', 'Yes', 'YES'):
                    for migration in further_migrations:
                        try:
                            chain_mod = self._get_migration_module(
                                migration['path'])
                        except Exception as e:
                            print('-' * 20, 'ERROR', '-' * 20)
                            print(
                                'Migration can not be reverted! Module import error - %s! Migration name - %s, '
                                'migration path - %s' %
                                (e, migration.get('name', ''), migration.get('path', '')))
                            print('-' * 45)
                            return

                        if not hasattr(mod, 'Migration'):
                            print('-' * 20, 'ERROR', '-' * 20)
                            print('Migration has no class Migration! Migration name - %s, migration path - %s' %
                                  (migration.get('name', ''), migration.get('path', '')))
                            print('-' * 45)
                            return

                        if not inspect.isclass(mod.Migration):
                            print('-' * 20, 'ERROR', '-' * 20)
                            print('Migration is not a class! Migration name - %s, migration path - %s' %
                                  (migration.get('name', ''), migration.get('path', '')))
                            print('-' * 45)
                            return

                        cls_parents = [c.__name__ for c in mod.Migration.__bases__]
                        if 'BaseMigration' not in cls_parents:
                            print('-' * 20, 'ERROR', '-' * 20)
                            print('Migration has no parent BaseMigration! Migration name - %s, migration path - %s' %
                                  (migration.get('name', ''), migration.get('path', '')))
                            print('-' * 45)
                            return

                        if not hasattr(mod.Migration, 'backwards_query'):
                            print('-' * 20, 'ERROR', '-' * 20)
                            print('Migration has no backwards_query! Migration name - %s, migration path - %s' %
                                  (migration.get('name', ''), migration.get('path', '')))
                            print('-' * 45)
                            return

                        backward_migration(
                            chain_mod.Migration(),
                            migration['name']
                        )
                    backward_migration(
                        mod.Migration(), name)
                    print('Successfully applied.')
                else:
                    print('Canceled.')
            else:
                print(f'Migration {name} does not found.')
        else:
            print(f'Migration {name} does not mentioned in '
                  f'migrations database table.')

    @staticmethod
    def __get_further_migrations(name: str):
        """
        Get all migrations after passed.
        """
        query = f"""
            SELECT file_name FROM migrations WHERE
            id > (SELECT id FROM migrations WHERE
            file_name = '{name}')
            """

        with app.db.get_cursor() as cur:
            cur.execute(query)
            return cur.fetchall()

    @staticmethod
    def __verify_migration_existence(
            file_name: str
            ) -> bool:
        """
        Verify that passed migration name exists in migrations
        datatable.
        """
        query = f"""
            SELECT * FROM migrations WHERE
            file_name = '{file_name}'
            """

        with app.db.get_cursor() as cur:
            cur.execute(query)
            if cur.fetchone():
                return True
        return False