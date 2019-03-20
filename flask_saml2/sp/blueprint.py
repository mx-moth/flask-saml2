from flask import Blueprint

from flask_saml2.exceptions import CannotHandleAssertion

from .views import (
    AssertionConsumer, CannotHandleAssertionView, Login, LoginIdP, Logout,
    Metadata, SingleLogout)


def create_blueprint(sp):
    idp_bp = Blueprint(sp.blueprint_name, 'flask_saml2.sp', template_folder='templates')

    idp_bp.add_url_rule('/login/', view_func=Login.as_view(
        'login', sp=sp))
    idp_bp.add_url_rule('/login/idp/', view_func=LoginIdP.as_view(
        'login_idp', sp=sp))
    idp_bp.add_url_rule('/logout/', view_func=Logout.as_view(
        'logout', sp=sp))
    idp_bp.add_url_rule('/acs/', view_func=AssertionConsumer.as_view(
        'acs', sp=sp))
    idp_bp.add_url_rule('/sls/', view_func=SingleLogout.as_view(
        'sls', sp=sp))
    idp_bp.add_url_rule('/metadata.xml', view_func=Metadata.as_view(
        'metadata', sp=sp))

    idp_bp.register_error_handler(CannotHandleAssertion, CannotHandleAssertionView.as_view(
        'cannot_handle_assertion', sp=sp))

    return idp_bp
