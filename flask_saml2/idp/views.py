import logging

from flask import Response, make_response, redirect, request, session, url_for
from flask.views import MethodView, View

from flask_saml2.exceptions import CannotHandleAssertion

from . import idp

logger = logging.getLogger(__name__)


class SAML2ViewMixin:
    def __init__(self, *, idp: 'idp.IdentityProvider', **kwargs):
        super().__init__(**kwargs)
        self.idp = idp


class SAML2View(SAML2ViewMixin, MethodView):
    pass


class LoginBegin(SAML2View):
    def get(self):
        return self.handle_login_request(
            request.args['SAMLRequest'], request.args.get('RelayState', ''))

    def post(self):
        return self.handle_login_request(
            request.form['SAMLRequest'], request.form.get('RelayState', ''))

    def handle_login_request(self, saml_request, relay_state):
        session['SAMLRequest'] = saml_request
        session['RelayState'] = relay_state
        return redirect(url_for('.login_process', _external=True))


class LoginProcess(SAML2View):
    def get(self):
        self.idp.login_required()

        saml_request = session['SAMLRequest']
        relay_state = session['RelayState']

        for handler in self.idp.get_sp_handlers():
            try:
                request = handler.parse_authn_request(saml_request)
                response = handler.make_response(request)
                context = handler.get_response_context(request, response, relay_state)
            except (CannotHandleAssertion, ValueError):
                logger.exception("%s could not handle login request", handler)
                pass
            else:
                return self.idp.render_template(
                    'flask_saml2_idp/login.html', **context)
        raise CannotHandleAssertion(
            "No Service Provider handlers could handle this SAML request")


class Logout(SAML2View):
    """
    Allows a non-SAML 2.0 URL to log out the user and
    returns a standard logged-out page. (Salesforce and others use this method,
    though it's technically not SAML 2.0).
    """
    def get(self):
        self.idp.login_required()
        self.idp.logout()

        for arg in ['RelayState', 'redirect_to']:
            if arg not in request.args:
                continue
            redirect_url = request.args[arg]
            if redirect_url and self.idp.is_valid_redirect(redirect_url):
                return redirect(redirect_url)

        return self.idp.render_template('flask_saml2_idp/logged_out.html')


class SLOLogoutBegin(SAML2View):
    """
    This is partially complete. Use the logout URL above, which actually does
    log people out.
    """
    def post(self):
        self.idp.login_required()

        saml_request = session['SAMLRequest']
        relay_state = session['RelayState']

        for handler in self.idp.get_sp_handlers():
            try:
                request = handler.parse_logout_request(saml_request)
                response = handler.make_response(request)
                context = handler.get_response_context(request, response, relay_state)
            except CannotHandleAssertion:
                logger.exception("%s could not handle login request", handler)
                pass
            else:
                return self.idp.render_template('flask_saml2_idp/login.html', **context)
        raise CannotHandleAssertion(
            "No Service Provider handlers could handle this SAML request")


class Metadata(SAML2View):
    """
    Replies with the XML Metadata IDPSSODescriptor.
    """
    def get(self):
        metadata = self.idp.render_template(
            'flask_saml2_idp/metadata.xml',
            **self.idp.get_metadata_context())

        response = make_response(metadata)
        response.headers['Content-Type'] = 'application/xml'
        return response


class UserNotAuthorizedView(SAML2ViewMixin, View):
    def dispatch_request(self, exception):
        logger.exception("User not authorized", exc_info=exception)
        return self.idp.render_template('flask_saml2_idp/invalid_user.html')


class CannotHandleAssertionView(SAML2ViewMixin, View):
    def dispatch_request(self, exception):
        logger.exception("Can not handle request", exc_info=exception)
        return Response(status=400)
