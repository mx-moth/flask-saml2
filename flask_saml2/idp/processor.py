import base64
import logging

from flask import session

from flask_saml2.exceptions import CannotHandleAssertion
from flask_saml2.utils import get_random_id, get_time_string

from .request import RequestProcessor
from .xml_render import get_response_xml


class Processor(object):
    """
    Base SAML 2.0 AuthnRequest to Response Processor.
    Sub-classes should provide Service Provider-specific functionality.
    """
    acs_url = None
    x509_cert = None

    request: RequestProcessor
    request_params: dict

    assertion_params = None
    assertion_xml = None

    saml_request = None
    relay_state = None

    subject_format = 'urn:oasis:names:tc:SAML:2.0:nameid-format:email'

    def __init__(self, name, adaptor, acs_url=None, x509_cert=None):
        self.name = name
        self.adaptor = adaptor
        self.logger = logging.getLogger(f'{self.__module__}.{type(self).__name__}')

        if acs_url is not None:
            self.acs_url = acs_url

        if x509_cert is not None:
            self.x509_cert = x509_cert

    @property
    def system_params(self):
        return {
            'ISSUER': self.adaptor.get_idp_config()['issuer'],
        }

    def build_assertion(self):
        """
        Builds assertion_params.
        """
        audience = self.get_audience()

        self.assertion_params = {
            'ASSERTION_ID': self.get_assertion_id(),
            'ASSERTION_SIGNATURE': '',  # it's unsigned
            'AUDIENCE': audience,
            'AUTH_INSTANT': get_time_string(),
            'ISSUE_INSTANT': get_time_string(),
            'NOT_BEFORE': get_time_string(hours=-1),
            'NOT_ON_OR_AFTER': get_time_string(minutes=15),
            'SESSION_NOT_ON_OR_AFTER': get_time_string(hours=8),
            'SP_NAME_QUALIFIER': audience,
            'SUBJECT': self.get_subject(),
            'SUBJECT_FORMAT': self.subject_format,
        }
        self.assertion_params.update(self.system_params)
        self.assertion_params.update(self.request_params)

    def build_response(self):
        """
        Builds _response_params.
        """
        self.response_params = {
            'ISSUE_INSTANT': get_time_string(),
            'RESPONSE_ID': self.get_response_id(),
            'RESPONSE_SIGNATURE': '',  # initially unsigned
        }
        self.response_params.update(self.system_params)
        self.response_params.update(self.request_params)

    def encode_response(self):
        """Encodes :attr:`Processor.response_xml`."""
        return base64.b64encode(self.response_xml.encode('utf-8')).decode('utf-8')

    def extract_saml_request(self):
        """
        Retrieves the saml_request AuthnRequest from the session and stores it
        as :attr:`saml_request` and :attr:`relay_state`.
        """
        self.saml_request = session['SAMLRequest']
        self.relay_state = session['RelayState']

    def format_assertion(self):
        """
        Formats :attr:`assertion_params` as XML and stores it as
        :attr:`assertion_xml`.
        """
        raise NotImplemented()

    def format_response(self):
        """
        Formats _response_params as _response_xml.
        """
        sign_it = self.adaptor.get_idp_config()['signing']

        self.response_xml = get_response_xml(
            self.response_params,
            self.assertion_xml,
            signed=sign_it,
            certificate=self.adaptor.get_idp_certificate(),
            private_key=self.adaptor.get_idp_private_key(),
        )

    def get_assertion_id(self):
        """Generates an ID for this assertion."""
        return get_random_id()

    def get_audience(self):
        """Gets the audience assertion parameter from the request data."""
        return self.request_params.get('DESTINATION', None) \
            or self.request_params.get('PROVIDER_NAME', None)

    def get_response_id(self):
        """Generate an ID for the response."""
        return get_random_id()

    def get_response_params(self):
        """Make a dictionary of parameters for the response template."""
        return {
            'acs_url': self.request_params['ACS_URL'],
            'saml_response': self.encode_response(),
            'relay_state': self.relay_state,
            'autosubmit': self.adaptor.get_idp_config()['autosubmit'],
        }

    def get_subject(self):
        """
        Get the subject of the assertion, based on the currently authenticated
        user and :attr:`Processor.subject_format`.
        """
        return self.adaptor.get_user_attribute(
            self.adaptor.get_current_user(), self.subject_format)

    def parse_request(self):
        """
        Parses various parameters from _request_xml into _request_params.
        """
        self.request.parse_request(self.x509_cert)

        self.request_params = {
            'ACS_URL': self.request.acs_url,
            'REQUEST_ID': self.request.request_id,
            'DESTINATION': self.request.destination,
            'PROVIDER_NAME': self.request.provider_name,
        }

    def validate_request(self):
        """
        Validates the SAML request against the SP configuration of this
        processor. Sub-classes should override this and raise a
        `CannotHandleAssertion` exception if the validation fails.

        Raises:
            CannotHandleAssertion: if the ACS URL specified in the SAML request
                doesn't match the one specified in the processor config.
        """
        request_acs_url = self.request_params['ACS_URL']

        if self.acs_url != request_acs_url:
            raise CannotHandleAssertion(f"Can't handle URL {request_acs_url}")

    def validate_user(self):
        """
        Validates the User. Sub-classes should override this and throw a
        CannotHandleAssertion exception if the validation does not succeed.
        """
        pass

    def get_request_processor(self, saml_request):
        """Get a :class:`~.request.RequestProcessor` to handle this request."""
        return RequestProcessor(saml_request)

    def handles_current_request(self):
        """
        Returns true if this processor can handle this request.
        """
        try:
            self.extract_saml_request()
        except Exception:
            self.logger.exception("can't find SAML request in user session")
            return False

        self.request = self.get_request_processor(self.saml_request)

        try:
            self.parse_request()
        except ValueError:
            self.logger.exception("can't parse SAML request")
            return False

        try:
            self.validate_request()
        except CannotHandleAssertion:
            return False

        return True

    def generate_response(self):
        """
        Processes request and returns template variables suitable for a response.
        """
        # Build the assertion and response.
        self.validate_user()

        self.build_assertion()
        self.format_assertion()

        self.build_response()
        self.format_response()

        # Return proper template params.
        return self.get_response_params()

    def init_deep_link(self, request, sp_config, url):
        """
        Initialize this Processor to make an IdP-initiated call to the SP's
        deep-linked URL.
        """
        self.reset(request, sp_config)
        acs_url = self.config['acs_url']
        # NOTE: The following request params are made up. Some are blank,
        # because they comes over in the AuthnRequest, but we don't have an
        # AuthnRequest in this case:
        # - Destination: Should be this IdP's SSO endpoint URL. Not used in the response?
        # - ProviderName: According to the spec, this is optional.
        self.request_params = {
            'ACS_URL': acs_url,
            'DESTINATION': '',
            'PROVIDER_NAME': '',
        }
        self.relay_state = url

    def is_valid_redirect(self, url):
        """
        Is this URL a valid redirect target back to this service provider?
        """
        return False
