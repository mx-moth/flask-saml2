import logging

from flask import Response, make_response, redirect, request, session, url_for
from flask.views import MethodView, View

from flask_saml2.utils import certificate_to_string

from .adaptor import Adaptor

logger = logging.getLogger(__name__)


class SAML2ViewMixin:
    def __init__(self, *, adaptor: Adaptor, **kwargs):
        super().__init__(**kwargs)
        self.adaptor = adaptor


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
        return redirect(url_for('.saml_login_process', _external=True))


class LoginProcess(SAML2View):
    def get(self):
        self.adaptor.login_required()
        processor = self.adaptor.get_processor_for_request()
        context = processor.generate_response()
        return self.adaptor.render_template('flask_saml2_idp/login.html', **context)


class Logout(SAML2View):
    """
    Allows a non-SAML 2.0 URL to log out the user and
    returns a standard logged-out page. (SalesForce and others use this method,
    though it's technically not SAML 2.0).
    """
    def get(self):
        self.adaptor.login_required()
        self.adaptor.logout()

        redirect_url = request.args.get('redirect_to', '')

        if self.adaptor.is_valid_redirect(redirect_url):
            return redirect(redirect_url)

        return self.adaptor.render_template('flask_saml2_idp/logged_out.html')


class SLOLogout(SAML2View):
    # FIXME Ported from dj-saml-idp, but this does not appear to be used?
    def post(self):
        self.adaptor.login_required()

        session['SAMLRequest'] = request.args.get('SAMLRequest')

        # TODO: Parse SAML LogoutRequest from POST data, similar to login_process().
        # TODO: Add a URL dispatch for this view.
        # TODO: Modify the base processor to handle logouts?
        # TODO: Combine this with login_process(), since they are so very similar?
        # TODO: Format a LogoutResponse and return it to the browser.
        # XXX: For now, simply log out without validating the request.
        self.adaptor.logout()

        return self.adaptor.render_template('flask_saml2_idp/logged_out.html')


class Metadata(SAML2View):
    """
    Replies with the XML Metadata IDPSSODescriptor.
    """
    def get(self):
        certificate = certificate_to_string(self.adaptor.get_idp_certificate())
        context = {
            'entity_id': self.adaptor.get_idp_config()['issuer'],
            'cert_public_key': certificate,
            'slo_url': url_for('.saml_logout', _external=True),
            'sso_url': url_for('.saml_login_begin', _external=True),
            'org': None,
            'contacts': [],
        }
        context.update(self.adaptor.get_metadata_context())

        metadata = self.adaptor.render_template('flask_saml2_idp/idpssodescriptor.xml', **context)

        response = make_response(metadata)
        response.headers['Content-Type'] = 'application/xml'
        return response


class UserNotAuthorizedView(SAML2ViewMixin, View):
    def dispatch_request(self, exception):
        logger.exception("User not authorized", exc_info=exception)
        return self.adaptor.render_template('flask_saml2_idp/invalid_user.html')


class CannotHandleAssertionView(SAML2ViewMixin, View):
    def dispatch_request(self, exception):
        logger.exception("Can not handle request", exc_info=exception)
        return Response(status=400)
