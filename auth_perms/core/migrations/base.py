"""
Migrations base module.
"""
from flask import current_app as app
from psycopg2.errors import DuplicateColumn
from psycopg2.errors import DuplicateObject
from psycopg2.errors import DuplicateTable
from psycopg2.errors import UndefinedColumn
from psycopg2.errors import UndefinedTable
from psycopg2.errors import UniqueViolation


def insert_to_migrations_table(name, file_name):
    """
    Insert applied migration to migrations table.
    """
    if not name:
        name = file_name

    query = f"""
        INSERT INTO migrations
        ("name", "file_name") VALUES ('{name}', '{file_name}')
        """

    with app.db.get_cursor() as cur:
        cur.execute(query)


def delete_from_migrations_table(file_name):
    """
    Delete applied migration from migrations table.
    """
    query = f"""
        DELETE FROM migrations WHERE
        file_name = '{file_name}'
        """

    with app.db.get_cursor() as cur:
        cur.execute(query)


def forward_migration(migration, table_name, file_name):
    """
    Forward migration and handle possible errors.
    """
    if not table_name:
        table_name = file_name

    try:
        migration.forwards()
        insert_to_migrations_table(table_name, file_name)
    except DuplicateTable:
        print(f'{table_name} already applied.')
    except UniqueViolation:
        print(f'{table_name} already applied.')
    except DuplicateObject as e:
        print(f'object applying in {file_name} already exists')
        if e.args:
            print(e.args[0])
    except DuplicateColumn as e:
        print(f'column already exists {file_name}')
        if e.args:
            print(e.args[0])
    except UndefinedColumn as e:
        print(f'column is undefined {file_name}')
        if e.args:
            print(e.args[0])


def backward_migration(migration, file_name):
    """
    Backward migration and handle possible errors.
    """
    try:
        migration.backwards()
        delete_from_migrations_table(file_name)
    except UndefinedTable as e:
        print(e)


class BaseMigration:
    """
    Base class for project migrations.
    """
    table_name = None
    forwards_query = None
    backwards_query = None

    def forwards(self):
        if not self.forwards_query:
            raise ValueError(
                'forwards_query can not be None or empty')

        with app.db.get_cursor() as cur:
            cur.execute(self.forwards_query)

    def backwards(self):
        if not self.backwards_query:
            raise ValueError(
                'backwards_query can not be None or empty')

        with app.db.get_cursor() as cur:
            cur.execute(self.backwards_query)
