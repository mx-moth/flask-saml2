from typing import Mapping

from flask_saml2.types import XmlNode
from flask_saml2.xml_parser import XmlParser


class ResponseParser(XmlParser):

    def is_signed(self):
        sig = self.xml_tree.xpath('/samlp:Response/ds:Signature', namespaces=self.get_namespace_map())
        return bool(sig)

    @property
    def issuer(self) -> str:
        return self._xpath_xml_tree('/samlp:Response/saml:Issuer')[0].text

    @property
    def response_id(self) -> str:
        return self._xpath_xml_tree('/samlp:Response/@ID')[0]

    @property
    def destination(self) -> str:
        try:
            return self._xpath_xml_tree('/samlp:Response/@Destination')[0]
        except IndexError:
            return ''

    @property
    def version(self) -> str:
        return self._xpath_xml_tree('/samlp:Response/@Version')[0]

    @property
    def issue_instant(self) -> str:
        return self._xpath_xml_tree('/samlp:Response/@IssueInstant')[0]

    @property
    def assertion(self) -> XmlNode:
        return self._xpath_xml_tree('/samlp:Response/saml:Assertion')[0]

    @property
    def subject(self) -> XmlNode:
        return self._xpath(self.assertion, 'saml:Subject')[0]

    @property
    def nameid(self) -> str:
        return self._xpath(self.subject, 'saml:NameID')[0].text

    @property
    def nameid_format(self) -> str:
        return self._xpath(self.subject, 'saml:NameID/@Format')[0]

    @property
    def attributes(self) -> Mapping[str, str]:
        attributes = self._xpath(self.assertion, 'saml:AttributeStatement/saml:Attribute')
        return {el.get('Name'): self._xpath(el, 'saml:AttributeValue')[0].text
                for el in attributes}
