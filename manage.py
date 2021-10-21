from config import app
from config import settings

from auth_perms import AuthPerms
from auth_perms.core.manage import init_manager

AuthPerms(app=app, settings_module=settings, config_mode=settings.CONFIG_MODE, is_manager=True)
manager = init_manager(app)

if __name__ == '__main__':
    manager.run()
