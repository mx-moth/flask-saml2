from flask import abort, current_app
from flask_login import current_user, logout_user

from flask_saml2.idp.adaptor import Adaptor


class FlaskLoginAdaptor(Adaptor):
    def login_required(self):
        if not current_user.is_authenticated:
            raise abort(current_app.login_manager.unauthorized())

    def logout(self):
        logout_user()

    def get_current_user(self):
        return current_user
