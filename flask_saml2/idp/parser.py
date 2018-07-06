from typing import Optional

from flask_saml2.types import XmlNode
from flask_saml2.xml_parser import XmlParser


class AuthnRequestParser(XmlParser):

    def is_signed(self):
        return bool(self._xpath_xml_tree('/samlp:AuthnRequest/ds:Signature'))

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


class LogoutRequestParser(XmlParser):

    def is_signed(self):
        return bool(self._xpath_xml_tree('/samlp:LogoutRequest/ds:Signature'))

    @property
    def issuer(self) -> str:
        return self._xpath_xml_tree('/samlp:LogoutRequest/saml:Issuer')[0].text

    @property
    def request_id(self) -> str:
        return self._xpath_xml_tree('/samlp:LogoutRequest/@ID')[0]

    @property
    def destination(self) -> Optional[str]:
        try:
            return self._xpath_xml_tree('/samlp:LogoutRequest/@Destination')[0]
        except IndexError:
            return None

    @property
    def version(self) -> str:
        return self._xpath_xml_tree('/samlp:LogoutRequest/@Version')[0]

    @property
    def issue_instant(self) -> str:
        return self._xpath_xml_tree('/samlp:LogoutRequest/@IssueInstant')[0]

    @property
    def nameid_el(self) -> XmlNode:
        return self._xpath_xml_tree('/samlp:LogoutRequest/saml:NameID')[0]

    @property
    def nameid(self) -> XmlNode:
        return self.nameid_el.text

    @property
    def nameid_format(self) -> XmlNode:
        return self._xpath(self.nameid_el, '@Format')[0]
