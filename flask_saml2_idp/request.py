import base64
import logging

import defusedxml.lxml
import lxml.etree
from signxml import XMLVerifier

from . import codex


class RequestProcessor:
    NS_MAP = {  # Namespace map
        'samlp': 'urn:oasis:names:tc:SAML:2.0:protocol',
        'saml': 'urn:oasis:names:tc:SAML:2.0:assertion',
        'ds': 'http://www.w3.org/2000/09/xmldsig#',
    }
    PARSE_MSG = 'parse_request must be called first'

    def __init__(self, saml_request: str):
        """
        :param saml_request: The SAML request provided by the client
        :param x509cert: A preshared x509_cert to validate signed requests with.
        """
        self._logger = logging.getLogger(__name__)
        self._saml_request = saml_request
        self.xml_tree = None
        self._signed = False
        self._signed_data = False
        self.x509_cert = None

    def _decode_request(self):
        """Decodes _request_xml from _saml_request."""
        self._request_xml = base64.b64decode(self._saml_request)

        # Is it XML yet?
        if not self._request_xml.strip().startswith(b'<'):
            # Try decode and inflate
            self._request_xml = codex.decode_base64_and_inflate(self._saml_request)

        self._logger.debug('SAML request decoded: '.format(self._request_xml))

    def parse_request(self, x509_cert: str = None) -> None:
        """
        Parse the SAML request.
        :param x509_cert str: The certificate that the request was signed with. Optional.
        :raises: ValueError
        """
        self._decode_request()
        # Minimal test to verify that it's not binarily encoded still:
        if not self._request_xml.strip().startswith(b'<'):
            msg = 'RequestXML is not valid XML; it may need to be decoded or decompressed.'
            self._logger.warning(msg)
            raise ValueError(msg)

        try:
            self.xml_tree = defusedxml.lxml.fromstring(self._request_xml)
        except lxml.etree.Error:
            message = "Could not parse request XML"
            self._logger.exception(message)
            raise ValueError(message)

        sig = self.xml_tree.xpath('/samlp:AuthnRequest/ds:Signature', namespaces=self.NS_MAP)
        if sig:
            self._signed = True
            self.parse_signed(x509_cert)

    def parse_signed(self, x509_cert: str = None):
        """
        Replaces all parameters with only the signed parameters. You should
        provide an x509 certificate obtained out-of-band, usually via the
        SAML metadata. Otherwise the signed data will be verified with only
        the certificate provided in the request. This is INSECURE and
        more-or-less only useful for testing.
        :param x509_cert:
        :return:
        """
        self._assert_xml_tree()
        self.xml_tree = XMLVerifier().verify(self.xml_tree, x509_cert=x509_cert).signed_xml
        self._signed_data = True

    def _assert_xml_tree(self):
        assert self.xml_tree is not None, self.PARSE_MSG

    def _xpath_xml_tree(self, xpath_statement):
        self._assert_xml_tree()
        return self.xml_tree.xpath(xpath_statement, namespaces=self.NS_MAP)

    @property
    def signed_data(self) -> bool:
        """
        Is the data provided by the class signed
        :return: True if the request data provided by this class is signed
        """
        self._assert_xml_tree()
        return self._signed_data

    @property
    def signed(self) -> bool:
        """
        Is the request signed
        :return: bool True if request is signed
        """
        self._assert_xml_tree()
        return self._signed

    @property
    def issuer(self) -> str:
        return self._xpath_xml_tree('/samlp:AuthnRequest/saml:Issuer')[0].text

    @property
    def request_id(self) -> str:
        return self._xpath_xml_tree('/samlp:AuthnRequest/@ID')[0]

    @property
    def destination(self) -> str:
        try:
            return self._xpath_xml_tree('/samlp:AuthnRequest/@Destination')[0]
        except IndexError:
            return ''

    @property
    def acs_url(self) -> str:
        return self._xpath_xml_tree('/samlp:AuthnRequest/@AssertionConsumerServiceURL')[0]

    @property
    def provider_name(self) -> str:
        try:
            return self._xpath_xml_tree('/samlp:AuthnRequest/@ProviderName')[0]
        except IndexError:
            return ''

    @property
    def version(self) -> str:
        return self._xpath_xml_tree('/samlp:AuthnRequest/@Version')[0]

    @property
    def issue_instant(self) -> str:
        return self._xpath_xml_tree('/samlp:AuthnRequest/@IssueInstant')[0]

    @property
    def protocol_binding(self) -> str:
        return self._xpath_xml_tree('/samlp:AuthnRequest/@ProtocolBinding')[0]
