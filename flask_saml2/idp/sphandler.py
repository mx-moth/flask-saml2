import base64
import datetime
import logging
from typing import Any, Optional
from urllib.parse import urlparse

from flask_saml2 import codex
from flask_saml2.exceptions import CannotHandleAssertion
from flask_saml2.signing import Digester, Signer
from flask_saml2.types import X509
from flask_saml2.utils import get_random_id, utcnow
from flask_saml2.xml_templates import XmlTemplate

from .parser import AuthnRequestParser, LogoutRequestParser
from .xml_templates import AssertionTemplate, ResponseTemplate


class SPHandler(object):
    """
    Handles incoming SAML requests from a specific Service Provider for
    a running Identity Provider.

    Sub-classes should provide Service Provider-specific functionality.
    """
    entity_id: str
    acs_url = None
    certificate: Optional[X509] = None
    display_name: str = None

    subject_format = 'urn:oasis:names:tc:SAML:2.0:nameid-format:email'
    assertion_template = AssertionTemplate
    response_template = ResponseTemplate

    # If the Service Provider uses the <AuthnRequest> Destination attribute
    require_destination = True

    def __init__(
        self, idp,
        *,
        entity_id: str,
        acs_url: str = None,
        certificate: Optional[X509] = None,
        display_name: str = None,
    ):
        self.idp = idp

        self.entity_id = entity_id
        self.logger = logging.getLogger(f'{self.__module__}.{type(self).__name__}')

        if acs_url is not None:
            self.acs_url = acs_url

        if certificate is not None:
            self.certificate = certificate

        if display_name:
            self.display_name = display_name

    @property
    def common_parameters(self):
        return {
            'ISSUER': self.idp.get_idp_entity_id(),
        }

    def get_sp_signer(self) -> Signer:
        """
        Get the :class:`~flask_saml2.signing.Signer` to use for this SP.
        Default to the one used by the IdP. If a particular SP requires
        a particular signing method, that SP can override it.
        """
        return self.idp.get_idp_signer()

    def get_sp_digester(self) -> Digester:
        """
        Get the :class:`~flask_saml2.signing.Digester` to use for this SP.
        Default to the one used by the IdP. If a particular SP requires
        a particular digest method, that SP can override it.
        """
        return self.idp.get_idp_digester()

    def build_assertion(
        self,
        request: AuthnRequestParser,
        issue_instant: datetime.datetime,
    ) -> dict:
        """Build parameters for the assertion template."""
        audience = self.get_audience(request)

        return {
            'ASSERTION_ID': self.get_assertion_id(),
            'AUDIENCE': audience,
            'IN_RESPONSE_TO': request.request_id,
            'AUTH_INSTANT': self.format_datetime(issue_instant),
            'ISSUE_INSTANT': self.format_datetime(issue_instant),
            'NOT_BEFORE': self.format_datetime(issue_instant + datetime.timedelta(minutes=-3)),
            'NOT_ON_OR_AFTER': self.format_datetime(issue_instant + datetime.timedelta(minutes=15)),
            'SESSION_NOT_ON_OR_AFTER': self.format_datetime(issue_instant + datetime.timedelta(hours=8)),
            'SP_NAME_QUALIFIER': audience,
            'SUBJECT': self.get_subject(),
            'SUBJECT_FORMAT': self.subject_format,
            **self.common_parameters,
            **self.extract_request_parameters(request),
        }

    def build_response(
        self,
        request: AuthnRequestParser,
        issue_instant: datetime.datetime,
    ) -> dict:
        """Build parameters for the response template."""
        return {
            'ISSUE_INSTANT': self.format_datetime(issue_instant),
            'RESPONSE_ID': self.get_response_id(),
            'IN_RESPONSE_TO': request.request_id,
            **self.common_parameters,
            **self.extract_request_parameters(request),
        }

    def encode_response(self, response: XmlTemplate):
        """Encodes the response XML template suitable for sending to the SP."""
        data = response.get_xml_string().encode('utf-8')
        return base64.b64encode(data).decode('utf-8')

    def format_assertion(self, assertion_params: dict) -> XmlTemplate:
        """Make a :class:`AssertionTemplate` to respond to this SP."""
        assertion = self.assertion_template(assertion_params)

        if self.idp.should_sign_responses():
            assertion.sign(
                certificate=self.idp.get_idp_certificate(),
                digester=self.get_sp_digester(),
                signer=self.get_sp_signer())

        return assertion

    def format_response(
        self,
        response_params: dict,
        assertion: XmlTemplate,
    ) -> XmlTemplate:
        """Make a :class:`ResponseTemplate` to respond to this SP."""
        response = self.response_template(response_params, assertion)

        if self.idp.should_sign_responses():
            response.sign(
                certificate=self.idp.get_idp_certificate(),
                signer=self.get_sp_signer(),
                digester=self.get_sp_digester())

        return response

    def get_assertion_id(self):
        """Generates an ID for this assertion."""
        return get_random_id()

    def get_audience(self, request: AuthnRequestParser) -> str:
        """Gets the audience assertion parameter from the request data."""
        return request.issuer or ''

    def get_response_id(self):
        """Generate an ID for the response."""
        return get_random_id()

    def get_response_context(
        self,
        request: AuthnRequestParser,
        response: XmlTemplate,
        relay_state: Any
    ):
        """Make a dictionary of parameters for the response template."""
        return {
            'handler': self,
            'acs_url': request.acs_url,
            'saml_response': self.encode_response(response),
            'relay_state': relay_state,
            'autosubmit': self.idp.get_idp_autosubmit(),
        }

    def get_subject(self):
        """
        Get the subject of the assertion, based on the currently authenticated
        user and :attr:`SPHandler.subject_format`.
        """
        return self.idp.get_user_nameid(
            self.idp.get_current_user(), self.subject_format)

    def extract_request_parameters(self, request: AuthnRequestParser) -> dict:
        """
        Fetches various parameters from the request into a dict.
        """
        return {
            'ACS_URL': request.acs_url,
            'REQUEST_ID': request.request_id,
            'DESTINATION': request.destination,
            'PROVIDER_NAME': request.provider_name,
        }

    def validate_request(self, request: AuthnRequestParser):
        """
        Validates the SAML request against the configuration of this Service
        Provider handler . Sub-classes should override this and raise a
        `CannotHandleAssertion` exception if the validation fails.

        Raises:
            CannotHandleAssertion: if the ACS URL specified in the SAML request
                doesn't match the one specified in the SP handler config.
        """

        self.validate_destination(request)
        self.validate_entity_id(request)
        self.validate_acs_url(request)

    def validate_destination(self, request: AuthnRequestParser):
        """
        Validate an ``<AuthnRequest>`` Destination attribute, if it is set.
        """
        if request.destination is not None:
            if self.idp.get_sso_url() != request.destination:
                raise CannotHandleAssertion(
                    f'Destination mismatch {self.idp.get_sso_url()} != {request.destination}')
        elif self.require_destination:
            raise CannotHandleAssertion(f'No <AuthnRequest> Destination attribute set')

    def validate_entity_id(self, request: AuthnRequestParser):
        """
        Validate that the ``<AuthnRequest>`` Issuer attribute matches this
        Service Provider.
        """
        if self.entity_id != request.issuer:
            raise CannotHandleAssertion(
                'AuthnRequest Issuer does not match expected Entity ID, '
                f'{self.entity_id} != {request.issuer}')

    def validate_acs_url(self, request: AuthnRequestParser):
        """
        Validate that the ``<AuthnRequest>`` AssertionConsumerServiceURL
        attribute matches the expected ACS URL for this Service Provider.
        """
        if self.acs_url != request.acs_url:
            raise CannotHandleAssertion(
                f'ACS URL mismatch {self.acs_url} != {request.acs_url}')

    def validate_user(self):
        """
        Validates the User. Sub-classes should override this and throw a
        CannotHandleAssertion exception if the validation does not succeed.
        """
        pass

    def decode_saml_string(self, saml_string: str) -> bytes:
        """Decode an incoming SAMLRequest into an XML string."""
        return codex.decode_saml_xml(saml_string)

    def parse_authn_request(self, saml_request) -> AuthnRequestParser:
        """Get a :class:`~.request.AuthnRequestParser` to handle this request."""
        return AuthnRequestParser(
            self.decode_saml_string(saml_request),
            certificate=self.certificate)

    def parse_logout_request(self, saml_request) -> LogoutRequestParser:
        """Get a :class:`~.request.LogoutRequestParser` to handle this request."""
        return LogoutRequestParser(
            self.decode_saml_string(saml_request),
            certificate=self.certificate)

    def make_response(self, request) -> XmlTemplate:
        """
        Process the request and make a :class:`~.xml_render.ResponseTemplate`.
        """
        self.validate_request(request)
        self.validate_user()

        issue_instant = utcnow()
        assertion = self.format_assertion(self.build_assertion(request, issue_instant))
        response = self.format_response(self.build_response(request, issue_instant), assertion)
        return response

    def is_valid_redirect(self, url):
        """
        Is this URL a valid redirect target back to this service provider?
        """
        acs_url = urlparse(self.acs_url)
        redirect_url = urlparse(url)
        return acs_url.netloc == redirect_url.netloc and\
            acs_url.scheme == redirect_url.scheme

    def format_datetime(self, value: datetime.datetime) -> str:
        """
        Format a datetime for this SP. Some SPs are picky about their date
        formatting, and don't support the format produced by
        :meth:`datetime.datetime.isoformat`.
        """
        return value.isoformat()

    def __str__(self):
        if self.display_name:
            return self.display_name
        return self.entity_id
