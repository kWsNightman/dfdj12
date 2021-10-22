from flask import render_template, url_for, g, request, session, redirect
from config import app
from config import settings
import json
from auth_perms import AuthPerms
from db_setup import session, FormModel

AuthPerms(app=app, settings_module=settings, config_mode=settings.CONFIG_MODE)


@app.route('/')
def index():
    return render_template('dfdj12/base.html')


@app.route('/form/', methods=['GET', 'POST'])
def form():
    if request.method == 'POST':
        result = {}
        for name, data in request.form.items():
            if name.startswith('name') and data:
                result[name] = data
        data = json.dumps(result)
        session.add(FormModel(data=data))
        session.commit()
        return redirect(url_for('result'), code=302)
    return render_template('dfdj12/dinamicformapp/dinamicform.html')


@app.route('/result')
def result():
    try:
        if g.actor.actor_type:
            data = session.query(FormModel).all()
            return render_template('dfdj12/dinamicformapp/completed.html', data=data)
    except AttributeError:
        return redirect(url_for('auth_submodule.authorization'))


if __name__ == '__main__':
    app.run()
