## Данный репозиторий был создан для пробы интегрировать Ecosystem54 во Flask приложение.

### Основу авторизации и регистрации выполняет сабмодуль auth_perms и встроеная страница регистрации .../authorization/
## Быстрый запуск:
* Установить пакеты из requirements.txt и requirements_full_list.txt
* Создать базу данных проекта и установить расширение uuid-ossp 
```postgresql
CREATE DATABASE database_name;
\c database_name
CREATE EXTENSION IF NOT EXISTS "uuid-ossp";
```
* Внести данные БД в конфигурационный файл проекта local_settings.py 
```python
DATABASE = {
    "ENGINE": "postgresql",
    "NAME": "",
    "USER": "",
    "PASSWORD": "",
    "HOST": "localhost",
    "PORT": "5432"
}
```
* Создать файл для запуска менеджера manage.py 
```python
# импортировать app и settings.py
from auth_perms import AuthPerms
from auth_perms.core.manage import init_manager

AuthPerms(app=app, settings_module=settings, config_mode=settings.CONFIG_MODE, is_manager=True)
manager = init_manager(app)


if __name__ == '__main__':
    manager.run()
```
* Создать файл для запуска проекта run.py 
```python
# импортировать app и settings.py
from flask import render_template
from auth_perms import AuthPerms

AuthPerms(app=app, settings_module=settings, config_mode=settings.CONFIG_MODE)


if __name__ == '__main__':
    app.run()
```
* Выполнить миграции
> python manage.py migrate
* Выполнить команду для создания сервиса 
> python manage.py create_service
* Занести выведенные в консоли данные в файл настроек local_settings.py
```python
SERVICE_UUID = "b7fcf8b6-e956-4e2e-a762-6ac95e04f8ce"
SERVICE_PUBLIC_KEY = "04a8ea40635e1ba9a848275c44b145780594490f9df5b8624995f3d22c9e9d1eec9f1fe78f2dd6b4637977a187f5f89b643e9e8af999bdbbf03df30477d90161f9"
SERVICE_PRIVATE_KEY = "e1ed67edc12170b9d2ca44c5342623ffb22b715e379554dc007879093ac5f296"
SERVICE_DOMAIN = "http://127.0.0.1:5000"
SERVICE_NAME = "test"
```
* Запустить проект через файл запуска проекта
> python run.py

####db_setup.py создал чтобы чуть больше разобраться в sqlalchemy и не сохранять данные из формы тестового в той же бд что и Ecosystem54 
####Сам сабмодуль не изменял 
####Пытался проверять авторизирован ли пользователь для получения страницы .../result

####Для этого во вью функции проверял в глобал обьекте Flask имеется ли actor
```python
# run.py

@app.route('/result')
def result():
    try:
        if g.actor.actor_type:
            data = session.query(FormModel).all()
            return render_template('dfdj12/dinamicformapp/completed.html', data=data)
    except AttributeError:
        return redirect(url_for('auth_submodule.authorization'))
```
#### Возможно выполнил не верно, и не понял как разлогинить пользователя