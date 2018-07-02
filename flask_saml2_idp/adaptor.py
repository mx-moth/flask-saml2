from flask import current_app, render_template

from .exceptions import CannotHandleAssertion
from .utils import import_string


class Adaptor(object):
    """
    Developers should subclass :class:`Adaptor` and implement all the methods
    to interoperate with their specific environment. All user interactions are
    performed through methods on this class.
    """

    # Configuration

    def get_idp_config(self):
        """
        Get the configuration for this IdP. See the PySAML2 documentation for
        what configuration options are available.

        The configuration should be a dict like:

        .. code-block:: python

            {
                'issuer': 'My Company',
                'autosubmit': True,
                'signing': True,
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

    def get_idp_certificate(self):
        return self.get_idp_config()['certificate']

    def get_idp_private_key(self):
        return self.get_idp_config()['private_key']

    def get_service_providers(self):
        """
        Get an iterable of service provider ``(name, config)`` pairs. ``name``
        is only used interally for logging and debugging. ``config`` should be
        a dict specifying a Provider subclass and optionally any constructor
        arguments:

        .. code-block:: python

            >>> list(adaptor.get_servic_providers())
            [('my_sp', {
                'PROCESSOR': 'my_app.provider.MySpProvider',
                'OPTIONS': {
                    'acs_url': 'https://service.example.com/auth/acs/',
                },
            })]

        Defaults to ``current_app.config['SAML2_SERVICE_PROVIDERS'].items()``.
        """
        return current_app.config['SAML2_SERVICE_PROVIDERS'].items()

    # Authentication

    def login_required(self):
        """
        Check if a user is currently logged in to this session, and
        :method:`flask.abort` with a redirect to the login page if not. It is
        suggested to use :meth:`is_user_logged_in`.
        """
        raise NotImplementedError

    def is_user_logged_in(self):
        raise NotImplementedError

    def logout(self):
        """
        Terminate the session for a logged in user.
        """
        raise NotImplementedError

    # User

    def get_current_user(self):
        raise NotImplementedError

    def get_user_attribute(self, user, attribute):
        """
        Get the requested attribute for the user. ``user`` will be the user
        returned from :meth:`get_current_user`. ``attribute`` will be an X.500
        attribute identifier.
        """
        if attribute == 'urn:oid:0.9.2342.19200300.100.1.1':
            return self.get_user_uid(user)

        if attribute in {
                'urn:oid:0.9.2342.19200300.100.1.3',
                'urn:oasis:names:tc:SAML:2.0:nameid-format:email',
        }:
            return self.get_user_email(user)

        raise NotImplementedError("Can't fetch attribute {} from user".format(attribute))

    def get_user_email(self, user):
        """Get the email address for a user."""
        return user.email

    def get_user_uid(self, user):
        """Get the username / user id for a user."""
        return user.username

    # Processors

    def get_processors(self):
        """
        Get the Processor for each service provider defined.
        """
        for name, config in self.get_service_providers():
            cls = import_string(config['PROCESSOR'])
            options = config.get('OPTIONS', {})
            yield cls(name, self, **options)

    def get_processor_for_request(self):
        """
        Find a Processor instance that can handle the current request.
        """
        for processor in self.get_processors():
            if processor.handles_current_request():
                return processor
        raise CannotHandleAssertion('No known processors could handle this request.')

    # Misc

    def render_template(self, template, **context):
        context = {
            'adaptor': self,
            **context,
        }
        return render_template(template, **context)

    def get_metadata_context(self):
        """
        Get any extra context for the metadata template. Suggested extra
        context variables include 'org' and 'contacts'.
        """
        return {}

    def is_valid_redirect(self, url):
        return any(
            processor.is_valid_redirect(url)
            for processor in self.get_processors()
        )
