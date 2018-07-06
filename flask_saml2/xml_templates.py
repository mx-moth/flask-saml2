"""
XML templates for SAML 2.0
"""
from typing import Iterable, Mapping, Optional

from lxml import etree

from flask_saml2.types import XmlNode

NAMESPACE_MAP: Mapping[str, str] = {  # Namespace map
    'samlp': 'urn:oasis:names:tc:SAML:2.0:protocol',
    'saml': 'urn:oasis:names:tc:SAML:2.0:assertion',
    'md': 'urn:oasis:names:tc:SAML:2.0:metadata',
    'ds': 'http://www.w3.org/2000/09/xmldsig#',
}


class XmlTemplate:

    namespace = None
    _xml = None

    def __init__(self, params: dict = {}):
        self.params = params.copy()

    def generate_xml(self):
        raise NotImplementedError

    def _get_xml(self) -> XmlNode:
        if self._xml is None:
            self._xml = self.generate_xml()
        return self._xml

    def _set_xml(self, xml: XmlNode):
        self._xml = xml

    xml = property(_get_xml, _set_xml)

    def get_xml_string(self):
        return etree.tostring(self.xml, method='c14n', exclusive=True).decode('utf-8')

    def element(
        self,
        tag: str,
        *,
        namespace: Optional[str] = None,
        attrs: Optional[Mapping[str, Optional[str]]] = None,
        children: Optional[Iterable[Optional[XmlNode]]] = None,
        text: Optional[str] = None
    ) -> XmlNode:
        """
        Shortcut for creating an ElementTree Element, with optional attributes,
        children, and text.

        :param tag str: tag to give XML element
        :param namespace str: Namespace to use for the element. Defaults to
            :meth:`get_namespace()` if None.
        :param attrs dict: Element attributes. If an attribute value is None,
            the attribute is ignored.
        :param children list: Element children. If an item in children is None,
            the item is ignored.
        :param text str: Element text content, if any.
        :return: xml.etree.ElementTree.Element
        """
        if namespace is None:
            namespace = self.get_namespace()

        tag_name = f'{{{namespace}}}{tag}'
        element = etree.Element(tag_name, nsmap=self.get_namespace_map())

        if attrs is not None:
            for k, v in attrs.items():
                if v is not None:
                    element.set(k, v)

        if children is not None:
            for child in children:
                if child is not None:
                    element.append(child)

        if text is not None:
            element.text = text

        return element

    def get_namespace_map(self) -> Mapping[str, str]:
        return NAMESPACE_MAP

    def get_namespace(self) -> str:
        return self.get_namespace_map()[self.namespace]


class SignedInfoTemplate(XmlTemplate):
    namespace = 'ds'

    def generate_xml(self):
        return self.element('SignedInfo', children=[
            self._get_canon_method(),
            self._get_signature_method(),
            self._get_reference(),
        ])

    def _get_canon_method(self):
        return self.element('CanonicalizationMethod', attrs={
            'Algorithm': 'http://www.w3.org/2001/10/xml-exc-c14n#'})

    def _get_signature_method(self):
        return self.element('SignatureMethod', attrs={
            'Algorithm': self.params['SIGNER'].uri})

    def _get_reference(self):
        return self.element('Reference', attrs={
            'URI': '#' + self.params['REFERENCE_URI']
        }, children=[
            self._get_tranforms(),
            self.element('DigestMethod', attrs={
                'Algorithm': self.params['DIGESTER'].uri,
            }),
            self.element('DigestValue', text=self.params['SUBJECT_DIGEST'])
        ])

    def _get_tranforms(self):
        return self.element('Transforms', children=[
            self.element('Transform', attrs={
                'Algorithm': 'http://www.w3.org/2000/09/xmldsig#enveloped-signature'
            }),
            self.element('Transform', attrs={
                'Algorithm': 'http://www.w3.org/2001/10/xml-exc-c14n#'
            }),
        ])

    """
    Not used, just left for reference
        <ds:SignedInfo xmlns:ds="http://www.w3.org/2000/09/xmldsig#">
            <ds:CanonicalizationMethod Algorithm="http://www.w3.org/2001/10/xml-exc-c14n#"></ds:CanonicalizationMethod>
            <ds:SignatureMethod Algorithm="http://www.w3.org/2000/09/xmldsig#rsa-sha1"></ds:SignatureMethod>
            <ds:Reference URI="#${REFERENCE_URI}">
                <ds:Transforms>
                    <ds:Transform Algorithm="http://www.w3.org/2000/09/xmldsig#enveloped-signature"></ds:Transform>
                    <ds:Transform Algorithm="http://www.w3.org/2001/10/xml-exc-c14n#"></ds:Transform>
                </ds:Transforms>
                <ds:DigestMethod Algorithm="http://www.w3.org/2000/09/xmldsig#sha1"></ds:DigestMethod>
                <ds:DigestValue>${SUBJECT_DIGEST}</ds:DigestValue>
            </ds:Reference>
        </ds:SignedInfo>
    """


class SignatureTemplate(XmlTemplate):
    namespace = 'ds'

    def generate_xml(self):
        return self.element('Signature', children=[
            self.params['SIGNED_INFO'],
            self._get_signature_value(),
            self._get_key_info(),
        ])

    def _get_signature_value(self):
        return self.element('SignatureValue', text=self.params['SIGNATURE'])

    def _get_key_info(self):
        return self.element('KeyInfo', children=[
            self.element('X509Data', children=[
                self.element('X509Certificate', text=self.params['CERTIFICATE'])
            ])
        ])
    """
    <ds:Signature xmlns:ds="http://www.w3.org/2000/09/xmldsig#">
            ${SIGNED_INFO}
        <ds:SignatureValue>${RSA_SIGNATURE}</ds:SignatureValue>
        <ds:KeyInfo>
            <ds:X509Data>
                <ds:X509Certificate>${CERTIFICATE}</ds:X509Certificate>
            </ds:X509Data>
        </ds:KeyInfo>
    </ds:Signature>
    """


class NameIDTemplate(XmlTemplate):
    namespace = 'saml'

    def generate_xml(self):
        return self.element('NameID', attrs={
            'Format': self.params['SUBJECT_FORMAT'],
            'SPNameQualifier': self.params.get('SP_NAME_QUALIFIER'),
        }, text=self.params['SUBJECT'])
