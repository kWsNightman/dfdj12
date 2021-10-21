"""
Base actor class with manager. This class is used to get actor object like ORM. Usage:
Actor.objects.get(key=value) - get single actor by sent params
Actor.objects.filter(key=value) - get list of actors by sent kwargs arguments
Actor.objects.exists(key=value) - is actor with params sent in kwargs exists.
Actor.objects.get_by_session(session_token=session_token) - get by session token
"""

import json

import requests
from datetime import datetime
from flask import current_app as app
from psycopg2 import sql
from psycopg2.extras import RealDictRow
from urllib.parse import urljoin

from .utils import get_static_group
from .utils import get_auth_domain
from .utils import json_dumps
from .utils import get_language_header
from .utils import sign_data
from .utils import verify_signature
from .utils import create_response_message
from flask_babel import gettext as _


class ActorNotFound(Exception):

    def __init__(self, *args, **kwargs):
        if args or kwargs:
            super().__init__(*args, *kwargs)
        else:
            message = 'No actor with such parameters found'
            super().__init__(message)


class FieldError(Exception):
    pass


class MultipleObjectsReturned(Exception):

    def __init__(self, *args, **kwargs):
        if args or kwargs:
            super().__init__(*args, *kwargs)
        else:
            message = 'get() returned more than one object.'
            super().__init__(message)


# TODO: Move base manager out of actor.py
class BaseManager:

    def __init__(self, table_name, *args, **kwargs):
        self.table_name = table_name

    def compile_query(self, *args, **kwargs):

        appends_list = list()
        values = dict()

        if not args:
            query_string = "SELECT * FROM {} "
        else:
            query_string = "SELECT " + ", ".join(['{}' for _ in args]) + "FROM {}"
            appends_list += list(args)
        appends_list.append(sql.Identifier(self.table_name))

        if kwargs:
            query_string += "WHERE "

        for k, v in kwargs.items():

            query_fragment, appends, value = self.parse_keyword(k, v)
            query_string += query_fragment
            query_string += " AND "
            appends_list += appends
            values.update(value)

        else:
            query_string = query_string.rstrip('AND ')

        query = sql.SQL(query_string).format(*appends_list)

        return query, values

    def exists_query(self, *args, **kwargs):

        appends_list = list()
        values = dict()
        query_string = "SELECT EXISTS(SELECT 1 FROM {} "

        appends_list.append(sql.Identifier(self.table_name))

        if kwargs:
            query_string += "WHERE "

        for k, v in kwargs.items():

            query_fragment, appends, value = self.parse_keyword(k, v)

            query_string += query_fragment
            query_string += " AND "
            appends_list += appends
            values.update(value)

        else:
            query_string = query_string.rstrip('AND ')

        query_string += ')'

        query = sql.SQL(query_string).format(*appends_list)

        return query, values

    @staticmethod
    def parse_keyword(attribute, value):

        elements = attribute.split('__')

        if len(elements) == 1:
            return '{}={}', [sql.Identifier(attribute), sql.Placeholder(attribute)], {attribute: value}

        elif len(elements) == 2:

            if elements[1] == 'in':
                attribute = elements[0]
                return '{} IN {}', [sql.Identifier(attribute), sql.Placeholder(attribute)], {attribute: tuple(value)}

            elif elements[1] == 'contains':
                value = '%' + value + '%'
                attribute = elements[0]
                return '{} LIKE {}', [sql.Identifier(attribute), sql.Placeholder(attribute)], {attribute: value}

        raise FieldError('Unsupported lookup')


class ActorManager(BaseManager):

    def get(self, **kwargs):

        if not kwargs:
            raise ValueError('No filter parameters provided')

        query, values = self.compile_query(**kwargs)

        with app.db.get_cursor() as cur:
            cur.execute(query, values)
            actor = cur.fetchall()

        if not actor:
            raise ActorNotFound

        if len(actor) > 1:
            raise MultipleObjectsReturned

        else:
            return Actor(actor[0])

    def filter(self, **kwargs):

        query, values = self.compile_query(**kwargs)

        with app.db.get_cursor() as cur:
            cur.execute(query, values)
            actors = cur.fetchall()

        if not actors:
            return []

        else:
            return [Actor(actor) for actor in actors]

    def exists(self, **kwargs):

        query, values = self.exists_query(**kwargs)

        with app.db.get_cursor() as cur:
            cur.execute(query, values)
            exists = cur.fetchone().get('exists')

        return exists

    @staticmethod
    def get_by_session(session_token=None):

        if not session_token:
            raise ValueError('Invalid session_token')

        else:
            with app.db.get_cursor() as cur:
                cur.execute("SELECT A.* FROM actor A INNER JOIN service_session_token S ON S.uuid = A.uuid "
                            "WHERE S.session_token=%s", (session_token,))
                actor = cur.fetchone()

                if not actor:
                    raise ActorNotFound

                else:
                    return Actor(actor)


class Actor:

    objects = ActorManager(table_name='actor')

    def __init__(self, actor: RealDictRow):
        self.uuid = actor.get('uuid')
        self.actor_type = actor.get('actor_type')
        self.created = actor.get('created')
        self.initial_key = actor.get('initial_key')
        self.root_perms_signature = actor.get('root_perms_signature')
        self.secondary_keys = actor.get('secondary_keys')
        self.uinfo = actor.get('uinfo')
        self.root = self.is_root

    def __str__(self):
        return f'Actor of type {self.actor_type}'

    def __repr__(self):
        return '<%s: %s>' % (self.__class__.__name__, self)

    def to_dict(self):
        return json.loads(json.dumps(self, default=lambda o: datetime.strftime(o, '%Y-%m-%d %H:%M:%S')
        if isinstance(o, datetime) else o.__dict__))

    def get_public_keys(self):
        """
        Get user ecdsa keys
        :return: initial ecdsa key, secondary ecdsa key
        """
        initial_key = self.initial_key.get('user_pub_key')
        secondary_keys = [key for key in self.secondary_keys.values()] if self.secondary_keys else list()

        return initial_key, secondary_keys

    def get_apt54(self):
        """
        Send POST request on auth for getting apt54
        :return: apt54
        """
        url = urljoin(get_auth_domain(), '/get_apt54/')

        data = dict()
        data['uuid'] = self.uuid
        data['service_uuid'] = app.config['SERVICE_UUID']
        data['signature'] = sign_data(app.config['SERVICE_PRIVATE_KEY'], json_dumps(data, sort_keys=True))

        response = requests.post(url, json=data, headers=get_language_header())

        if response.ok:
            data = json.loads(response.content)
            signature = data.get('signature')
            user_data = str(data.get('user_data')) + str(data.get('expiration'))

            if verify_signature(app.config['AUTH_PUB_KEY'], signature, user_data):
                return data

        return None

    def get_groups(self):
        """
        Get list of actor groups
        :return: list of groups
        """
        if self.actor_type in ('user', 'classic_user'):
            groups = self.uinfo.get('groups') if self.uinfo.get('groups') else []
            list_of_groups = [self.objects.get(uuid=group) for group in groups]
            return list_of_groups
        return []

    def get_actors(self):
        """
        Get list of group members
        :return: list of actors
        """
        if self.actor_type == 'group':
            query = """SELECT uuid, uinfo FROM actor WHERE %s in (SELECT jsonb_array_elements_text(uinfo->'groups'))"""
            values = [self.uuid]
            with app.db.get_cursor() as cur:
                cur.execute(query, values)
                users = [Actor(user) for user in cur.fetchall()]
            list_of_users = [self.objects.get(uuid=user.uuid) for user in users]
            return list_of_users
        return []

    @property
    def is_root(self):
        """
        Check if user root
        :return: True if root, False if not
        """
        if not self.root_perms_signature or not self.initial_key:
            return False

        if app.config.get('AUTH_STANDALONE'):
            if not verify_signature(app.config['SERVICE_PUBLIC_KEY'], self.root_perms_signature,
                                    self.uuid + self.initial_key):
                return False
        else:
            if not verify_signature(app.config['AUTH_PUB_KEY'], self.root_perms_signature,
                                    self.uuid + self.initial_key):
                return False

        return True

    @property
    def is_banned(self):
        """
        Check if user in BAN group
        :return: True if in BAN, False if not
        """
        ban_group_uuid = get_static_group('BAN')
        if not ban_group_uuid:
            # If someone delete BAN group so everyone in BAN
            # TODO: uncomment return True if need upper solution
            # return True
            return False

        ban_group_uuid = ban_group_uuid.get('uuid')
        if self.uinfo.get('groups'):
            if ban_group_uuid in self.uinfo.get('groups'):
                return True

        return False

    @property
    def is_admin(self):
        admin_group_uuid = get_static_group('ADMIN')
        if not admin_group_uuid:
            # If someone delete ADMIN group so there is no admins
            return False

        admin_group_uuid = admin_group_uuid.get('uuid')
        if self.uinfo.get('groups'):
            if admin_group_uuid in self.uinfo.get('groups'):
                return True

        return False

    def get_permissions(self):
        """
        All permissions assigned to actor and his groups
        :return: dict with permissions
        """
        query = """SELECT collect_full_list_of_default_actor_groups_perms(%s);"""
        permissions = app.db.fetchall(query, [self.uuid])
        return permissions[0].get('collect_full_list_of_default_actor_groups_perms')

    def set_permission(self, perms: list):
        """
        Set permissions to actor
        :param perms: [{"uuid": permission_uuid, "value": 0 or 1}]
        :return: response
        """
        query = """WITH perms(data) AS (select json_array_elements(%s)) INSERT INTO permissions (created, service_id,
                   perm_id, actor_id, perm_value, default_value, perm_type, action_id, description) SELECT created,
                   service_id, perm_id, %s, (select data->>'value' from perms where data->>'uuid'=uuid::text)::smallint,
                   default_value, perm_type, action_id, description FROM permissions WHERE uuid IN %s"""
        perms_uuids = [perm['uuid'] for perm in perms]
        values = [json_dumps(perms), self.uuid, tuple(perms_uuids)]
        with app.db.get_cursor() as cur:
            cur.execute(query, values)
        response = create_response_message(message=_("Permission successfully granted."))
        return response, 200

    def remove_permission(self, perms: list):
        """
        Remove permissions from actor
        :param perms: list of permissions uuids
        :return: response
        """
        query = """DELETE FROM permissions WHERE uuid IN %s AND actor_id = %s"""
        values = [tuple(perms), self.uuid]
        with app.db.get_cursor() as cur:
            cur.execute(query, values)
        response = create_response_message(message=_("Permission successfully removed."))
        return response, 200

    def update_permission(self, perms: list):
        """
        Update permissions for actor
        :param perms: [{"uuid": permission_uuid, "value": 0 or 1}]
        :return: response
        """
        query = """WITH perms(data) AS (select json_array_elements(%s)) UPDATE permissions SET perm_value = (SELECT
                   data->>'value' FROM perms WHERE data->>'uuid' = uuid::text)::smallint WHERE actor_id=%s AND 
                   uuid IN %s"""
        perms_uuids = [perm['uuid'] for perm in perms]
        values = [json_dumps(perms), self.uuid, tuple(perms_uuids)]
        with app.db.get_cursor() as cur:
            cur.execute(query, values)
        response = create_response_message(message=_("Permission successfully updated."))
        return response, 200


class PermissionManager(BaseManager):

    def get(self, **kwargs):

        if not kwargs:
            raise ValueError('No filter parameters provided')

        query, values = self.compile_query(**kwargs)

        with app.db.get_cursor() as cur:
            cur.execute(query, values)
            permission = cur.fetchall()

        if not permission:
            raise ActorNotFound

        if len(permission) > 1:
            raise MultipleObjectsReturned

        else:
            return Permission(permission[0])

    def filter(self, **kwargs):

        query, values = self.compile_query(**kwargs)

        with app.db.get_cursor() as cur:
            cur.execute(query, values)
            permissions = cur.fetchall()

        if not permissions:
            return []

        else:
            return [Permission(permission) for permission in permissions]


class Permission:

    objects = PermissionManager(table_name='permissions')

    def __init__(self, permission: RealDictRow):
        self.uuid = permission.get('uuid')
        self.created = permission.get('created')
        self.service_id = permission.get('service_id')
        self.perm_id = permission.get('perm_id')
        self.actor_id = permission.get('actor_id')
        self.perm_value = permission.get('perm_value')
        self.default_value = permission.get('default_value')
        self.perm_type = permission.get('perm_type')
        self.action_id = permission.get('action_id')
        self.description = permission.get('description')

    def __str__(self):
        return f'{self.description.strip()}'

    def __repr__(self):
        return '<%s: %s>' % (self.__class__.__name__, self)
