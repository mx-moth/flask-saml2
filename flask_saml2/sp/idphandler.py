from typing import Mapping, Optional
from urllib.parse import urlencode

import attr

from flask_saml2 import codex
from flask_saml2.signing import sign_query_parameters
from flask_saml2.types import X509
from flask_saml2.utils import get_random_id, get_time_string
from flask_saml2.xml_templates import XmlTemplate

from .parser import ResponseParser
from .xml_templates import AuthnRequest, LogoutRequest


@attr.s(auto_attribs=True)
class AuthData:
    handler: 'IdPHandler'
    nameid: str
    nameid_format: str
    attributes: Mapping[str, str]
    session_id: str = None

    def to_dict(self) -> dict:
        """
        Return a dict of all attributes. You can store this dict in a session
        store, and recreate this instance using :meth:`from_dict`.
        """
        return {
            **attr.asdict(self),
            'handler': self.handler.name,
        }

    @classmethod
    def from_dict(cls, sp, data: dict):
        """
        Construct an :class:`AuthData` instance from a dict such as
        :meth:`to_dict` produces.
        """
        return cls(**{
            **data,
            'handler': sp.get_idp_handler_by_name(data['handler']),
        })


class IdPHandler:
    """
    Represents an Identity Provider that the running Service Provider knows
    about. This class should be subclassed for Identity Providers that need
    specific configurations.
    """
    display_name: Optional[str] = None
    certificate: Optional[X509] = None

    def __init__(
        self,
        name: str,
        sp,
        *,
        display_name: Optional[str] = None,
        sso_url: Optional[str] = None,
        slo_url: Optional[str] = None,
        certificate: Optional[X509] = None,
        **kwargs,
    ):
        """
        Construct a new IdPHandler.

        ``name`` is the internal name of this Identity Provider. It will be
        used to construct URLs. ``sp`` is the :class:`~.sp.ServiceProvider`
        instance that is running this Service Provider.

        ``display_name`` will be shown to users when they have a choice of
        IdP's to authenticate against, falling back to the ``name`` if this is
        not provided.

        ``sso_url`` and ``slo_url`` are the SSO and SLO URLs on the IdP. These
        are optional if you override :meth:`get_idp_sso_url` and
        :meth:`get_idp_slo_url`.

        ``certificate`` is the public X509 certificate of the IdP.

        The ``sso_url``, ``slo_url``, and ``certificate`` can all be found in
        the IdP's metadata.
        """
        super().__init__(**kwargs)

        self.name = name
        self.sp = sp

        if display_name is not None:
            self.display_name = display_name
        if sso_url is not None:
            self.sso_url = sso_url
        if slo_url is not None:
            self.slo_url = slo_url
        if certificate is not None:
            self.certificate = certificate

    def get_idp_sso_url(self):
        """Get the Single Sign On URL for this IdP."""
        return self.sso_url

    def get_idp_slo_url(self):
        """Get the Single Log Out URL for this IdP."""
        return self.slo_url

    def get_sp_acs_url(self):
        """
        Get the Attribute Consumer Service URL on the current SP this IdP
        should send responses to.
        """
        return self.sp.get_acs_url(self)

    def get_authn_request(
        self,
        template=AuthnRequest,
        **parameters,
    ):
        """
        Make a AuthnRequest to send to this IdP.
        """
        return template({
            'REQUEST_ID': get_random_id(),
            'ISSUE_INSTANT': get_time_string(),
            'DESTINATION': self.get_idp_sso_url(),
            'ISSUER': self.sp.get_sp_issuer(),
            'ACS_URL': self.get_sp_acs_url(),
            **parameters,
        })

    def get_logout_request(
        self,
        auth_data: AuthData,
        template: XmlTemplate = LogoutRequest,
        **parameters,
    ):
        """
        Make a LogoutRequest for the authenticated user to send to this IdP.
        """
        return template({
            'REQUEST_ID': get_random_id(),
            'ISSUE_INSTANT': get_time_string(),
            'DESTINATION': self.get_idp_slo_url(),
            'ISSUER': self.sp.get_sp_issuer(),
            'SUBJECT': auth_data.nameid,
            'SUBJECT_FORMAT': auth_data.nameid_format,
            **parameters,
        })

    def make_login_request_url(
        self,
        relay_state: Optional[str] = None,
    ) -> str:
        """Make a LoginRequest url and query string for this IdP."""
        authn_request = self.get_authn_request()
        saml_request = self.encode_saml_string(authn_request.get_xml_string())

        parameters = [('SAMLRequest', saml_request)]
        if relay_state is not None:
            parameters.append(('RelayState', relay_state))

        return self._make_idp_request_url(self.get_idp_sso_url(), parameters)

    def make_logout_request_url(
        self,
        auth_data: AuthData,
        relay_state: Optional[str] = None,
    ) -> str:
        logout_request = self.get_logout_request(auth_data)
        saml_request = self.encode_saml_string(logout_request.get_xml_string())

        parameters = [('SAMLRequest', saml_request)]
        if relay_state is not None:
            parameters.append(('RelayState', relay_state))

        return self._make_idp_request_url(self.get_idp_slo_url(), parameters)

    def _make_idp_request_url(self, url, parameters):
        """
        Make a URL to the SAML IdP, signing the query parameters if required.
        """
        if self.sp.should_sign_requests():
            query = sign_query_parameters(self.sp.get_sp_signer(), parameters)
        else:
            query = urlencode(parameters).encode('utf-8')

        return f'{url}?{query}'

    def decode_saml_string(self, saml_string: str) -> bytes:
        """Decode an incoming SAMLResponse into an XML string."""
        return codex.decode_saml_xml(saml_string)

    def encode_saml_string(self, saml_string: str) -> str:
        """Encoding an XML string into a SAMLRequest."""
        return codex.deflate_and_base64_encode(saml_string)

    def get_response_parser(self, saml_response):
        """Get a :class:`~.parser.ResponseParser` to handle this request."""
        return ResponseParser(
            self.decode_saml_string(saml_response),
            certificate=self.certificate)

    def get_auth_data(self, response: ResponseParser) -> AuthData:
        """Create an :class:`AuthData` instance from a SAML Response."""
        return AuthData(
            handler=self,
            nameid=response.nameid,
            nameid_format=response.nameid_format,
            attributes=response.attributes,
        )

    def __str__(self):
        if self.display_name:
            return self.display_name
        return self.name
