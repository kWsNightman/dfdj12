from pathlib import Path

BASE_DIR = Path(__file__).parent
DATABASE = {
    'ENGINE': 'postgresql',
    'NAME': '',
    'USER': '',
    'PASSWORD': '',
    'HOST': 'localhost',
}

# Flask secret key
APP_SECRET_KEY = None
DEBUG = True

LANGUAGES = ['en', 'ru', 'ch']
BABEL_DEFAULT_LOCALE = 'en'
SQLALCHEMY_TRACK_MODIFICATIONS = False
CONFIG_MODE = "DEVELOPMENT"
DEFAULT_GROUP_NAME = "DEFAULT"
SESSION_STORAGE = "SESSION"

try:
    from local_settings import *
except ImportError:
    pass

# ORM SQLALCHEMY database credentials
SQLALCHEMY_DATABASE_URI = '{ENGINE}://{USER}:{PASSWORD}@{HOST}/{NAME}'.format(**DATABASE)

