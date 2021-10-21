import sys
from flask_script import Manager

from .manager_commands.action import CollectActions
from .manager_commands.migration import MigrateBackwards
from .manager_commands.migration import MigrateForwards
from .manager_commands.permission import CollectPerms
from .manager_commands.translate import translate_manager
from .manager_commands.root_user import CreateRootUser
from .manager_commands.create_service import CreateService
from .manager_commands.connect_biom import ConnectBiom
from .manager_commands.disconnect_biom import DisconnectBiom
from .manager_commands.test import RunTests
from .managers import DatabaseManager

sys.path.append('../')


def init_manager(application, database=None):
    if not hasattr(application, 'db'):
        if not database:
            print('There is no database manager in main app or database credentials for registering this manager. '
                  'Please add database dict in manager init_app function')
            return

        database_manager = DatabaseManager(database=database)
        database_manager.init_app(application)

    manager = Manager(application)
    manager.add_command('migrate', MigrateForwards())
    manager.add_command('undo_migration', MigrateBackwards())
    manager.add_command('collect_actions', CollectActions())
    manager.add_command('collect_perms', CollectPerms())
    manager.add_command('translate', translate_manager)
    manager.add_command('run_tests', RunTests())
    manager.add_command('create_root', CreateRootUser())
    manager.add_command('create_service', CreateService())
    manager.add_command('connect_biom', ConnectBiom())
    manager.add_command('disconnect_biom', DisconnectBiom())
    return manager
