DATABASE = {
    "ENGINE": "postgresql",
    "NAME": "auth_perms",
    "USER": "auth_perms_user",
    "PASSWORD": "1234",
    "HOST": "localhost",
    "PORT": "5432"}
SECRET_KEY = "qwerty"
REDIRECT_URL = "http://127.0.0.1:8000/"
AUTH_STANDALONE = True
SESSION_STORAGE = "SESSION"
SOCKET_ASYNC_MODE = "gevent"
CONFIG_MODE = "DEVELOPMENT"
LANGUAGES_INFORMATION = [
    {
        "code": "en",
        "name": ("English")
    },
    {
        "code": "ru",
        "name": ("Russian")
    },
    {
        "code": "cn",
        "name": ("Chinese"),
        "block": True
    }
]
SERVICE_UUID = "b7fcf8b6-e956-4e2e-a762-6ac95e04f8ce"
SERVICE_PUBLIC_KEY = "04a8ea40635e1ba9a848275c44b145780594490f9df5b8624995f3d22c9e9d1eec9f1fe78f2dd6b4637977a187f5f89b643e9e8af999bdbbf03df30477d90161f9"
SERVICE_PRIVATE_KEY = "e1ed67edc12170b9d2ca44c5342623ffb22b715e379554dc007879093ac5f296"
SERVICE_DOMAIN = "http://127.0.0.1:5000"
SERVICE_NAME = "test"
