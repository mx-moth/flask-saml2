from flask import Blueprint

from flask_saml2.exceptions import CannotHandleAssertion, UserNotAuthorized

from .views import (
    CannotHandleAssertionView, LoginBegin, LoginProcess, Logout, Metadata,
    UserNotAuthorizedView)


def create_blueprint(idp):
    idp_bp = Blueprint('flask_saml2_idp', 'flask_saml2.idp', template_folder='templates')

    idp_bp.add_url_rule('/login/', view_func=LoginBegin.as_view(
        'login_begin', idp=idp))
    idp_bp.add_url_rule('/login/process/', view_func=LoginProcess.as_view(
        'login_process', idp=idp))

    idp_bp.add_url_rule('/logout/', view_func=Logout.as_view(
        'logout', idp=idp))

    idp_bp.add_url_rule('/metadata.xml', view_func=Metadata.as_view(
        'metadata', idp=idp))

    idp_bp.register_error_handler(CannotHandleAssertion, CannotHandleAssertionView.as_view(
        'cannot_handle_assertion', idp=idp))
    idp_bp.register_error_handler(UserNotAuthorized, UserNotAuthorizedView.as_view(
        'user_not_authorized', idp=idp))

    return idp_bp
