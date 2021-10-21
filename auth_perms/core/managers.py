import re
import psycopg2.extras
import psycopg2.extras
from contextlib import contextmanager
from flask import request
from flask import session
from flask import _request_ctx_stack
from flask import current_app
from flask import has_request_context
from psycopg2 import OperationalError
from psycopg2 import pool
from psycopg2.extensions import connection as connection_type
from psycopg2.extensions import cursor as cursor_type
from psycopg2.extras import RealDictCursor
from psycopg2.extras import RealDictRow
from psycopg2.pool import PoolError
from psycopg2.pool import SimpleConnectionPool
from typing import AnyStr
from typing import Iterable
from typing import List
from typing import Optional

from .actor import Actor
from .exceptions import DatabaseError
from .mixins import AnonymousUserMixin
from .mixins import UserMixin


# TODO: choose between this variant or .utils :467 user_context_processor()
class UserManager(object):
    """
    Manager for getting current user from context_processor. For example on jinja2 template {{ current_user }}.
    Return UserMixin if user has session token of AnonymousUserMixin if user has not session token
    """

    def __init__(self, app=None, add_context_processor=True):
        self.anonymous_user = AnonymousUserMixin
        if app:
            self.init_app(app, add_context_processor)

    def init_app(self, app, add_context_processor=True):
        app.user_manager = self
        if add_context_processor:
            app.context_processor(self._add_user_context_processor)

    def _add_user_context_processor(self):
        return dict(current_user=self._get_user())

    @staticmethod
    def _get_user():
        if has_request_context() and not hasattr(_request_ctx_stack, 'user'):
            current_app.user_manager.load_user()

        user = getattr(_request_ctx_stack.top, 'user', None)
        if not user:
            return AnonymousUserMixin()
        return UserMixin(user)

    def load_user(self):
        session_token = None
        if current_app.config.get('SESSION_STORAGE'):
            if current_app.config.get('SESSION_STORAGE') == 'HEADERS':
                session_token = request.headers.get('Session-Token', None)
            elif current_app.config.get('SESSION_STORAGE') == 'SESSION':
                session_token = session.get('session_token', None)
        else:
            if 'Session-Token' in request.headers or 'session_token' in session:
                session_token = request.headers.get('Session-Token')
                if not session_token:
                    session_token = session.get('session_token')

        if session_token:
            user = Actor.objects.get_by_session(session_token=session_token)

            if user:
                user = user.to_dict()

            if not user:
                return None

            self._update_context(user)

            return user

        return None

    @staticmethod
    def _update_context(user=None):
        ctx = _request_ctx_stack.top
        ctx.user = user


class DatabaseManager(object):
    """
    Base database manager.
    Creates pool with connections (default 10), automatically closing connection, create new connection
    if pool is empty, base methods like execute, fetchone, fetchall.
    """
    def __init__(self, database=None, dsn=None, min_connection: int = 1, max_connections: int = 10) -> None:
        if not database and not dsn:
            raise DatabaseError('Database credentials or DSN is required')

        if database:
            self.validate_database_dict(database)

        if dsn:
            self.validate_database_dsn(dsn)

        self.DATABASE = database
        self.DSN = dsn
        self.pool = self.create_pool(min_connection=min_connection, max_connections=max_connections)
        self.connection = self.create_connection()
        self.cursor = None

    def init_app(self, app):
        app.db = self

    @staticmethod
    def validate_database_dict(database):
        if not database:
            raise DatabaseError('Database credentials are required')

        if not isinstance(database, dict):
            raise DatabaseError('Database credentials should be dictionary')

        if not database.get('NAME', None):
            raise DatabaseError('Database NAME is required param')

        if not database.get('USER', None):
            raise DatabaseError('Database USER is required param')

        if not database.get('PASSWORD', None):
            raise DatabaseError('Database PASSWORD is required param')

        if not database.get('HOST', None):
            raise DatabaseError('Database HOST is required param')

    @staticmethod
    def validate_database_dsn(dsn):
        engine, user, password, host, port, db_name = re.split(r"://|@|:|/", dsn)
        if not engine:
            raise DatabaseError('There is no engine in dsn')

        if not user:
            raise DatabaseError('There is no user in dsn')

        if not password:
            raise DatabaseError('There is no password in dsn')

        if not host:
            raise DatabaseError('There is no host in dsn')

        if not port:
            raise DatabaseError('There is no port in dsn')

        if not db_name:
            raise DatabaseError('There is no port in db_name')

    @staticmethod
    def _get_cursor(connection: connection_type, cursor_factory: cursor_type) -> cursor_type:
        """
        Create cursor by connection
        :param connection: connection
        :param cursor_factory: type of needed cursor
        :return: cursor
        """
        cursor = connection.cursor(cursor_factory=cursor_factory)
        return cursor

    def close_connections(self) -> None:
        """
        Close all connections in pool
        """
        self.pool.closeall()

    def put_connection(self, connection: connection_type, key=None, close: bool = False) -> None:
        """
        Replace connection in pool cache
        :param connection: connection
        :param key:
        :param close: Flag if need close connection
        """
        try:
            self.pool.putconn(connection)
        except Exception as e:
            print('Error put connection')
            connection.close()

    def get_connection(self, autocommit: bool = True, key=None) -> connection_type:
        """
        Getting connection object
        :param autocommit: boolean if connection is autocommit
        :param key:
        :return: connection
        """
        try:
            connection = self.pool.getconn(key=key)
        except PoolError:
            connection = self.create_connection()
        except OperationalError:
            connection = self.connection
        connection.autocommit = autocommit
        return connection

    def create_connection(self) -> connection_type:
        if self.DATABASE:

            port = self.DATABASE.get("PORT") or "5432"
            self.DATABASE.update(PORT=port)
            conn = psycopg2.connect("dbname={NAME} user={USER} password={PASSWORD} host={HOST} "
                                    "port={PORT}".format(**self.DATABASE))
        elif self.DSN:
            conn = psycopg2.connect("{}".format(self.DSN))
        else:
            raise DatabaseError('There is no any database credentials')

        return conn

    @contextmanager
    def get_cursor(self, cursor_factory: Optional[cursor_type] = RealDictCursor, autocommit: bool = True):
        try:
            connection = self.get_connection(autocommit=autocommit)
            cur = self._get_cursor(connection, cursor_factory=cursor_factory)
            yield cur
        except PoolError:
            pass
        else:
            cur.close()
            self.put_connection(connection)

    @property
    def cur(self, cursor_factory: Optional[cursor_type] = RealDictCursor, autocommit: bool = True) -> cursor_type:

        try:
            connection = self.get_connection(autocommit=autocommit)
            cursor = self._get_cursor(connection, cursor_factory=cursor_factory)
        except PoolError:
            connection = self.create_connection()
            connection.autocommit = autocommit
            cursor = self._get_cursor(connection, cursor_factory=cursor_factory)

        return cursor

    def close_cursor(self, cursor) -> None:
        if cursor:
            cursor.close()
            self.put_connection(cursor.connection)

    def create_pool(self, min_connection: int, max_connections: int) -> SimpleConnectionPool:
        """
        Creates postgres connection pool
        """
        if self.DATABASE:
            port = self.DATABASE.get("PORT") or "5432"
            con_pool = psycopg2.pool.SimpleConnectionPool(minconn=min_connection, maxconn=max_connections,
                                                          user=self.DATABASE.get('USER'),
                                                          password=self.DATABASE.get('PASSWORD'),
                                                          host=self.DATABASE.get('HOST'), port=port,
                                                          database=self.DATABASE.get('NAME'))
        elif self.DSN:
            con_pool = psycopg2.pool.SimpleConnectionPool(minconn=min_connection, maxconn=max_connections,
                                                          dsn=self.DSN)
        else:
            raise DatabaseError('There is no any database credentials')

        return con_pool

    def fetchall(self, query: AnyStr, values: Iterable = None) -> List[RealDictRow]:
        """
        Fetch all records matching query from db
        :param query: SQL query string
        :param values: values to populate query string
        :return: matched records from DB
        """

        cur = self.cur

        try:
            cur.execute(query, values)
            result = cur.fetchall()
            self.close_cursor(cur)
        except Exception as e:
            self.close_cursor(cur)
            raise e

        return result

    def fetchone(self, query: AnyStr, values: Iterable = None)-> RealDictRow:
        """
        Fetch one record matching query from db
        :param query: SQL query string
        :param values: values to populate query string
        :return: matched records from DB
        """

        cur = self.cur

        try:
            cur.execute(query, values)
            result = cur.fetchone()
            self.close_cursor(cur)
        except Exception as e:
            self.close_cursor(cur)
            raise e

        return result

    def execute(self, query: AnyStr, values: Iterable = None) -> None:
        """
        Execute query
        :param query: SQL query string
        :param values: values to populate query string
        """

        cur = self.cur

        try:
            cur.execute(query, values)
            self.close_cursor(cur)
        except Exception as e:
            self.close_cursor(cur)
            raise e
