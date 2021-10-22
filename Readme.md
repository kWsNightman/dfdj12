## Данный репозиторий был создан для пробы интегрировать Ecosystem54 во Flask приложение.

### Основу авторизации и регистрации выполняет сабмодуль auth_perms и встроеная страница регистрации .../authorization/

#### db_setup.py создал чтобы чуть больше разобраться в sqlalchemy и не сохранять данные из формы тестового в той же бд что и Ecosystem54 
#### Сам сабмодуль не изменял 
#### Пытался проверять авторизирован ли пользователь для получения страницы .../result

#### Для этого во вью функции проверял в глобал обьекте Flask имеется ли actor
```python
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
