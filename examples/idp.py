#!/usr/bin/env python3
import logging

from flask import Flask, abort, redirect, request, session, url_for
from flask.views import MethodView

from flask_saml2.idp import IdentityProvider
from tests.idp.base import CERTIFICATE, PRIVATE_KEY, User
from tests.sp.base import CERTIFICATE as SP_CERTIFICATE

logger = logging.getLogger(__name__)


class ExampleIdentityProvider(IdentityProvider):
    def login_required(self):
        if not self.is_user_logged_in():
            next = url_for('login', next=request.url)

            abort(redirect(next))

    def is_user_logged_in(self):
        return 'user' in session and session['user'] in users

    def logout(self):
        del session['user']

    def get_current_user(self):
        return users[session['user']]


users = {user.username: user for user in [
    User('alex', 'alex@example.com'),
    User('jordan', 'jordan@example.com'),
]}


idp = ExampleIdentityProvider()


class Login(MethodView):
    def get(self):
        options = ''.join(f'<option value="{user.username}">{user.email}</option>'
                          for user in users.values())
        select = f'<div><label>Select a user: <select name="user">{options}</select></label></div>'

        next_url = request.args.get('next')
        next = f'<input type="hidden" name="next" value="{next_url}">'

        submit = '<div><input type="submit" value="Login"></div>'

        form = f'<form action="." method="post">{select}{next}{submit}</form>'
        header = '<title>Login</title><p>Please log in to continue.</p>'

        return header + form

    def post(self):
        user = request.form['user']
        next = request.form['next']

        session['user'] = user
        logging.info("Logged user", user, "in")
        logging.info("Redirecting to", next)

        return redirect(next)


app = Flask(__name__)
app.debug = True
app.secret_key = 'not a secret'
app.config['SERVER_NAME'] = 'localhost:8000'
app.config['SAML2_IDP'] = {
    'autosubmit': True,
    'certificate': CERTIFICATE,
    'private_key': PRIVATE_KEY,
}
app.config['SAML2_SERVICE_PROVIDERS'] = [
    {
        'CLASS': 'tests.idp.base.AttributeSPHandler',
        'OPTIONS': {
            'display_name': 'Example Service Provider',
            'entity_id': 'http://localhost:9000/saml/metadata.xml',
            'acs_url': 'http://localhost:9000/saml/acs/',
            'certificate': SP_CERTIFICATE,
        },
    }
]

app.add_url_rule('/login/', view_func=Login.as_view('login'))
app.register_blueprint(idp.create_blueprint(), url_prefix='/saml/')


if __name__ == '__main__':
    app.run(host='0.0.0.0', port=8000)
