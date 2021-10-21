from flask_babel import gettext as _
from flask import current_app as app

from ..actor import Actor
from ..actor import ActorNotFound
from ..action import BaseAction
from ..decorators import perms_check
from ..decorators import set_attributes
from ..utils import create_response_message
from ..utils import create_session
from ..utils import get_apt54


class GetPhantomActorListAction(BaseAction):

    def __init__(self, target_actor):
        self.target_actor = target_actor

    @perms_check
    def get_phantom_actors(self):
        query = """SELECT PR.uuid AS uuid, A.uinfo AS actor_uinfo FROM phantom_relation AS PR JOIN actor AS A 
        ON PR.phantom_actor=A.uuid WHERE PR.target_actor = %s"""
        phantom_list = app.db.fetchall(query, [self.target_actor.uuid])
        return phantom_list if phantom_list else []

    @set_attributes(**{'action_type': 'simple', 'default_value': 0})
    def biom_perm001(self):
        """
        Can get available phantom actors list
        """
        return True


class SetChosenPhantomActorAction(BaseAction):

    def __init__(self, phantom_uuid, target_actor_uuid):
        self.phantom_uuid = phantom_uuid
        self.target_actor_uuid = target_actor_uuid

    @perms_check
    def set_phantom_actor(self):
        query = """SELECT * FROM phantom_relation WHERE uuid = %s"""
        phantom_relation = app.db.fetchone(query, [self.phantom_uuid])
        if not phantom_relation:
            response = create_response_message(message=_("Invalid phantom relation unique identifier."), error=True)
            return response

        try:
            phantom_actor = Actor.objects.get(uuid=phantom_relation.get('phantom_actor'))
        except ActorNotFound:
            response = create_response_message(message=_("Invalid phantom actor data type. "
                                                         "Should be unique identifier."), error=True)
            return response

        try:
            target_actor = Actor.objects.get(uuid=self.target_actor_uuid)
        except ActorNotFound:
            response = create_response_message(message=_("Invalid target phantom actor data type. "
                                                         "Should be unique identifier."), error=True)
            return response

        query = """SELECT EXISTS(SELECT 1 FROM phantom_relation WHERE phantom_actor=%s AND target_actor=%s)"""
        if not app.db.fetchone(query, [phantom_actor.uuid, target_actor.uuid]).get('exists'):
            response = create_response_message(message=_("You can't use this function."), error=True)
            return response

        data, status_code = get_apt54(uuid=phantom_actor.uuid)
        if status_code == 452:
            response = create_response_message(message=_("There is no such actor."), error=True)
            return response
        elif status_code != 200:
            return data

        session_token = create_session(apt54=data)
        response = dict(
            session_token=session_token
        )
        return response

    @set_attributes(**{'action_type': 'simple', 'default_value': 0})
    def biom_perm001(self):
        """
        Can use phantom actor
        """
        return True
