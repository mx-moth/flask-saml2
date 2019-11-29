from typing import Generic, Iterable, Optional, Tuple, TypeVar

from flask import Blueprint, current_app, render_template, url_for

from flask_saml2.exceptions import CannotHandleAssertion, UserNotAuthorized
from flask_saml2.signing import Digester, RsaSha1Signer, Sha1Digester, Signer
from flask_saml2.types import X509, PKey
from flask_saml2.utils import certificate_to_string, import_string

from .sphandler import SPHandler
from .views import (
    CannotHandleAssertionView, LoginBegin, LoginProcess, Logout, Metadata,
    UserNotAuthorizedView)

U = TypeVar('User')


class IdentityProvider(Generic[U]):
    """
    Developers should subclass :class:`IdentityProvider`
    and provide methods to interoperate with their specific environment.
    All user interactions are performed through methods on this class.

    Every subclass should implement :meth:`is_user_logged_in`,
    :meth:`login_required`, :meth:`logout`, and :meth:`get_current_user`
    as a minimum.
    Other methods can be overridden as required.
    """

    blueprint_name = 'flask_saml2_idp'

    #: The specific :class:`digest <~flask_saml2.signing.Digester>` method to
    #: use in this IdP when creating responses.
    #:
    #: See also: :meth:`get_idp_digester`,
    #: :meth:`~.sp.SPHandler.get_sp_digester`.
    idp_digester_class: Digester = Sha1Digester

    #: The specific :class:`signing <~flask_saml2.signing.Signer>` method to
    #: use in this IdP when creating responses.
    #:
    #: See also: :meth:`get_idp_signer`,
    #: :meth:`~.sp.SPHandler.get_sp_signer`.
    idp_signer_class: Signer = RsaSha1Signer

    # Configuration

    def get_idp_config(self) -> dict:
        """
        Get the configuration for this IdP.
        Defaults to ``SAML2_IDP`` from :attr:`flask.Flask.config`.
        The configuration should be a dict like:

        .. code-block:: python

            {
                # Should the IdP automatically redirect the user back to the
                # Service Provider once authenticated.
                'autosubmit': True,
                # The X509 certificate and private key this IdP uses to
                # encrypt, validate, and sign payloads.
                'certificate': ...,
                'private_key': ...,
            }

        To load the ``certificate`` and ``private_key`` values, see

        - :func:`~.utils.certificate_from_string`
        - :func:`~.utils.certificate_from_file`
        - :func:`~.utils.private_key_from_string`
        - :func:`~.utils.private_key_from_file`
        """
        return current_app.config['SAML2_IDP']

    def should_sign_responses(self) -> bool:
        return self.get_idp_certificate() is not None \
            and self.get_idp_private_key() is not None

    def get_idp_entity_id(self) -> str:
        """The unique identifier for this Identity Provider.
        By default, this uses the metadata URL for this IdP.

        See :func:`get_metadata_url`.
        """
        return self.get_metadata_url()

    def get_idp_certificate(self) -> Optional[X509]:
        """Get the public certificate for this IdP.
        If this IdP does not sign its requests, returns None.
        """
        return self.get_idp_config().get('certificate')

    def get_idp_private_key(self) -> Optional[PKey]:
        """Get the private key for this IdP.
        If this IdP does not sign its requests, returns None.
        """
        return self.get_idp_config().get('private_key')

    def get_idp_autosubmit(self) -> bool:
        """Should the IdP autosubmit responses to the Service Provider?"""
        return self.get_idp_config().get('autosubmit', False)

    def get_idp_signer(self) -> Optional[Signer]:
        """Get the signing algorithm used by this IdP."""
        private_key = self.get_idp_private_key()
        if private_key is not None:
            return self.idp_signer_class(private_key)

    def get_idp_digester(self) -> Digester:
        """Get the method used to compute digests for the IdP."""
        return self.idp_digester_class()

    def get_service_providers(self) -> Iterable[Tuple[str, dict]]:
        """
        Get an iterable of service provider ``config`` dicts. ``config`` should
        be a dict specifying a SPHandler subclass and optionally any
        constructor arguments:

        .. code-block:: python

            >>> list(idp.get_service_providers())
            [{
                'CLASS': 'my_app.service_providers.MySPSPHandler',
                'OPTIONS': {
                    'acs_url': 'https://service.example.com/auth/acs/',
                },
            }]

        Defaults to ``current_app.config['SAML2_SERVICE_PROVIDERS']``.
        """
        return current_app.config['SAML2_SERVICE_PROVIDERS']

    def get_sso_url(self):
        """Get the URL for the Single Sign On endpoint for this IdP."""
        return url_for(self.blueprint_name + '.login_begin', _external=True)

    def get_slo_url(self):
        """Get the URL for the Single Log Out endpoint for this IdP."""
        return url_for(self.blueprint_name + '.logout', _external=True)

    def get_metadata_url(self):
        """Get the URL for the metadata XML document for this IdP."""
        return url_for(self.blueprint_name + '.metadata', _external=True)

    # Authentication

    def login_required(self):
        """Check if a user is currently logged in to this session, and
        :func:`flask.abort` with a redirect to the login page if not. It is
        suggested to use :meth:`is_user_logged_in`.
        """
        raise NotImplementedError

    def is_user_logged_in(self) -> bool:
        """Return True if a user is currently logged in.
        Subclasses should implement this method
        """
        raise NotImplementedError

    def logout(self):
        """Terminate the session for a logged in user.
        Subclasses should implement this method.
        """
        raise NotImplementedError

    # User

    def get_current_user(self) -> U:
        """Get the user that is currently logged in.
        """
        raise NotImplementedError

    def get_user_nameid(self, user: U, attribute: str):
        """Get the requested name or identifier from the user. ``attribute`` will
        be a ``urn:oasis:names:tc:SAML:2.0:nameid-format``-style urn.

        Subclasses can override this to allow more attributes to be extracted.
        By default, only email addresses are extracted using :meth:`get_user_email`.
        """
        if attribute == 'urn:oasis:names:tc:SAML:2.0:nameid-format:email':
            return self.get_user_email(user)

        raise NotImplementedError("Can't fetch attribute {} from user".format(attribute))

    def get_user_email(self, user: U):
        """Get the email address for a user."""
        return user.email

    # SPHandlers

    def get_sp_handlers(self) -> Iterable[SPHandler]:
        """Get the SPHandler for each service provider defined.
        """
        for config in self.get_service_providers():
            cls = import_string(config['CLASS'])
            options = config.get('OPTIONS', {})
            yield cls(self, **options)

    # Misc

    def render_template(self, template: str, **context) -> str:
        """Render an HTML template.
        This method can be overridden to inject more context variables if required.
        """
        context = {'idp': self, **context}
        return render_template(template, **context)

    def get_metadata_context(self) -> dict:
        """Get any extra context for the metadata template.
        Suggested extra context variables include 'org' and 'contacts'.
        """
        return {
            'entity_id': self.get_idp_entity_id(),
            'certificate': certificate_to_string(self.get_idp_certificate()),
            'slo_url': self.get_slo_url(),
            'sso_url': self.get_sso_url(),
            'org': None,
            'contacts': [],
        }

    def is_valid_redirect(self, url: str) -> bool:
        """Check if a URL is a valid and safe URL to redirect to,
        according to any of the SPHandlers.
        Only used from the non-standard logout page,
        for non-compliant Service Providers such as Salesforce.
        """
        return any(
            handler.is_valid_redirect(url)
            for handler in self.get_sp_handlers()
        )

    def create_blueprint(self):
        """Create a blueprint for this IdP.
        This blueprint needs to be registered with a Flask application
        to expose the IdP functionality.
        """
        bp = Blueprint(self.blueprint_name, 'flask_saml2.idp', template_folder='templates')

        bp.add_url_rule('/login/', view_func=LoginBegin.as_view(
            'login_begin', idp=self))
        bp.add_url_rule('/login/process/', view_func=LoginProcess.as_view(
            'login_process', idp=self))

        bp.add_url_rule('/logout/', view_func=Logout.as_view(
            'logout', idp=self))

        bp.add_url_rule('/metadata.xml', view_func=Metadata.as_view(
            'metadata', idp=self))

        bp.register_error_handler(CannotHandleAssertion, CannotHandleAssertionView.as_view(
            'cannot_handle_assertion', idp=self))
        bp.register_error_handler(UserNotAuthorized, UserNotAuthorizedView.as_view(
            'user_not_authorized', idp=self))

        return bp
