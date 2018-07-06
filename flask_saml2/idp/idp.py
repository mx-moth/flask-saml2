from typing import Generic, Iterable, Optional, Tuple, TypeVar

from flask import current_app, render_template, url_for

from flask_saml2.signing import Digester, RsaSha1Signer, Sha1Digester, Signer
from flask_saml2.types import X509, PKey
from flask_saml2.utils import certificate_to_string, import_string

from .sphandler import SPHandler

U = TypeVar('User')


class IdentityProvider(Generic[U]):
    """
    Developers should subclass :class:`IdentityProvider` and implement all the
    methods to interoperate with their specific environment. All user
    interactions are performed through methods on this class.
    """

    # Configuration

    def get_idp_config(self) -> dict:
        """
        Get the configuration for this IdP. See the PySAML2 documentation for
        what configuration options are available.

        The configuration should be a dict like:

        .. code-block:: python

            {
                'issuer': 'My Company',
                'autosubmit': True,
                'certificate': ...,
                'private_key': ...,
            }

        See
        :func:`.utils.certificate_from_string`,
        :func:`.utils.certificate_from_file`,
        :func:`.utils.private_key_from_string`, and
        :func:`.utils.private_key_from_file`
        for loading the ``certificate`` and ``private_key`` files.

        Defaults to ``current_app.config['SAML2_IDP']``.
        """
        return current_app.config['SAML2_IDP']

    def should_sign_responses(self) -> bool:
        return self.get_idp_certificate() is not None \
            and self.get_idp_private_key() is not None

    def get_idp_entity_id(self) -> str:
        return url_for('.metadata', _external=True)

    def get_idp_certificate(self) -> Optional[X509]:
        """Get the public certificate for this IdP."""
        return self.get_idp_config().get('certificate')

    def get_idp_private_key(self) -> Optional[PKey]:
        """Get the private key for this IdP."""
        return self.get_idp_config().get('private_key')

    def get_idp_issuer(self) -> str:
        return self.get_idp_config().get('issuer', '')

    def get_idp_autosubmit(self) -> bool:
        return self.get_idp_config().get('autosubmit', False)

    def get_idp_signer(self) -> Optional[Signer]:
        """Get the signing algorithm used by this IdP."""
        private_key = self.get_idp_private_key()
        if private_key is not None:
            return RsaSha1Signer(private_key)

    def get_idp_digester(self) -> Digester:
        return Sha1Digester()

    def get_service_providers(self) -> Iterable[Tuple[str, dict]]:
        """
        Get an iterable of service provider ``(name, config)`` pairs. ``name``
        is only used interally for logging and debugging. ``config`` should be
        a dict specifying a SPHandler subclass and optionally any constructor
        arguments:

        .. code-block:: python

            >>> list(idp.get_service_providers())
            [('my_sp', {
                'CLASS': 'my_app.service_providers.MySPSPHandler',
                'OPTIONS': {
                    'acs_url': 'https://service.example.com/auth/acs/',
                },
            })]

        Defaults to ``current_app.config['SAML2_SERVICE_PROVIDERS'].items()``.
        """
        return current_app.config['SAML2_SERVICE_PROVIDERS'].items()

    # Authentication

    def login_required(self) -> None:
        """
        Check if a user is currently logged in to this session, and
        :method:`flask.abort` with a redirect to the login page if not. It is
        suggested to use :meth:`is_user_logged_in`.
        """
        raise NotImplementedError

    def is_user_logged_in(self) -> bool:
        raise NotImplementedError

    def logout(self) -> None:
        """
        Terminate the session for a logged in user.
        """
        raise NotImplementedError

    # User

    def get_current_user(self) -> U:
        raise NotImplementedError

    def get_user_nameid(self, user: U, attribute: str):
        """
        Get the requested name or identifier from the user. ``attribute`` will
        be a ``urn:oasis:names:tc:SAML:2.0:nameid-format``-style urn.
        """
        if attribute == 'urn:oasis:names:tc:SAML:2.0:nameid-format:email':
            return self.get_user_email(user)

        raise NotImplementedError("Can't fetch attribute {} from user".format(attribute))

    def get_user_email(self, user: U):
        """Get the email address for a user."""
        return user.email

    # SPHandlers

    def get_sp_handlers(self) -> Iterable[SPHandler]:
        """
        Get the SPHandler for each service provider defined.
        """
        for name, config in self.get_service_providers():
            cls = import_string(config['CLASS'])
            options = config.get('OPTIONS', {})
            yield cls(name, self, **options)

    # Misc

    def render_template(self, template: str, **context) -> str:
        context = {
            'idp': self,
            **context,
        }
        return render_template(template, **context)

    def get_metadata_context(self) -> dict:
        """
        Get any extra context for the metadata template. Suggested extra
        context variables include 'org' and 'contacts'.
        """
        return {
            'entity_id': self.get_idp_entity_id(),
            'certificate': certificate_to_string(self.get_idp_certificate()),
            'slo_url': url_for('.logout', _external=True),
            'sso_url': url_for('.login_begin', _external=True),
            'org': None,
            'contacts': [],
        }

    def is_valid_redirect(self, url: str) -> bool:
        return any(
            handler.is_valid_redirect(url)
            for handler in self.get_sp_handlers()
        )
