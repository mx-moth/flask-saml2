"""
XML templates for SAML 2.0
"""
import typing as T

import lxml.etree as ET

from . import types as TS

NAMESPACE_MAP: T.Mapping[str, str] = {  # Namespace map
    'samlp': 'urn:oasis:names:tc:SAML:2.0:protocol',
    'saml': 'urn:oasis:names:tc:SAML:2.0:assertion',
    'md': 'urn:oasis:names:tc:SAML:2.0:metadata',
    'ds': 'http://www.w3.org/2000/09/xmldsig#',
}


class XmlTemplate:

    namespace = None
    _xml = None

    def __init__(self, params: dict = None):
        if params is None:
            self.params = {}
        else:
            self.params = params
        self._xml = None

    def generate_xml(self):
        raise NotImplementedError

    def _get_xml(self) -> TS.XmlNode:
        if self._xml is None:
            self._xml = self.generate_xml()
        return self._xml

    def _set_xml(self, xml: ET.Element):
        self._xml = xml

    xml = property(_get_xml, _set_xml)

    def get_xml_string(self):
        return ET.tostring(self.xml, method='c14n', exclusive=True).decode('utf-8')

    def element(
        self,
        tag: str,
        *,
        namespace: T.Optional[str] = None,
        attrs: T.Optional[T.Mapping[str, T.Optional[str]]] = None,
        children: T.Optional[T.List[T.Optional[TS.XmlNode]]] = None,
        text: T.Optional[str] = None
    ) -> TS.XmlNode:
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
        element = ET.Element(tag_name, nsmap=self.get_namespace_map())

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

    def get_namespace_map(self) -> T.Mapping[str, str]:
        return NS_MAP

    def get_namespace(self) -> str:
        return self.get_namespace()[self.namespace]


class SignedInfoTemplate(XmlTemplate):
    namespace = 'ds'

    def generate_xml(self):
        return self.element('SignedInfo', children=[
            self._get_canon_method(),
            self._get_signature_method(),
            self._get_reference(),
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

    def _get_reference(self):
        return self.element('Reference', attrs={
            'URI': '#' + self.params['REFERENCE_URI']
        }, children=[
            self._get_tranforms(),
            self.element('DigestMethod', attrs={
                'Algorithm': 'http://www.w3.org/2000/09/xmldsig#sha1',
            }),
            self.element('DigestValue', text=self.params['SUBJECT_DIGEST'])
        ])

    def _get_signature_method(self):
        return self.element('SignatureMethod', attrs={
            'Algorithm': 'http://www.w3.org/2000/09/xmldsig#rsa-sha1'})

    def _get_canon_method(self):
        return self.element('CanonicalizationMethod', attrs={
            'Algorithm': 'http://www.w3.org/2001/10/xml-exc-c14n#'})

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
        return self.element('SignatureValue', text=self.params['RSA_SIGNATURE'])

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


class AttributeTemplate(XmlTemplate):
    namespace = 'saml'

    def generate_xml(self):
        return self.element('Attribute', attrs={
            'Name': self.params['ATTRIBUTE_NAME'],
            'NameFormat': 'urn:oasis:names:tc:SAML:2.0:attrname-format:basic',
        }, children=[
            self.element('AttributeValue', text=self.params['ATTRIBUTE_VALUE']),
        ])

    """
        <saml:Attribute Name="${ATTRIBUTE_NAME}" NameFormat="urn:oasis:names:tc:SAML:2.0:attrname-format:basic">
            <saml:AttributeValue>${ATTRIBUTE_VALUE}</saml:AttributeValue>
        </saml:Attribute>
    """


class AttributeStatementTemplate(XmlTemplate):
    namespace = 'saml'

    def generate_xml(self):
        attributes = self.params.get('ATTRIBUTES', {})
        if not attributes:
            return None

        return self.element('AttributeStatement', children=[
            AttributeTemplate({'ATTRIBUTE_NAME': name, 'ATTRIBUTE_VALUE': value}).xml
            for name, value in attributes.items()
        ])

    """
        <saml:AttributeStatement>
        ${ATTRIBUTES}
        </saml:AttributeStatement>
    """


class SubjectTemplate(XmlTemplate):
    namespace = 'saml'

    def generate_xml(self):
        return self.element('Subject', children=[
            self._get_name_id_xml(),
            self._get_subject_conf_xml(),
        ])

    def _get_name_id_xml(self):
        return self.element('NameID', attrs={
            'Format': self.params['SUBJECT_FORMAT'],
            'SPNameQualifier': self.params['SP_NAME_QUALIFIER'],
        }, text=self.params['SUBJECT'])

    def _get_subject_conf_xml(self):
        scd_attributes = {
            'NotOnOrAfter': self.params['NOT_ON_OR_AFTER'],
            'Recipient': self.params['ACS_URL'],
        }
        if 'REQUEST_ID' in self.params:
            scd_attributes['InResponseTo'] = self.params['REQUEST_ID']

        return self.element('SubjectConfirmation', attrs={
            'Method': 'urn:oasis:names:tc:SAML:2.0:cm:bearer',
        }, children=[
            self.element('SubjectConfirmationData', attrs=scd_attributes),
        ])

    """
        <saml:Subject>
            <saml:NameID Format="${SUBJECT_FORMAT}" SPNameQualifier="${SP_NAME_QUALIFIER}">
            ${SUBJECT}
            </saml:NameID>
            <saml:SubjectConfirmation Method="urn:oasis:names:tc:SAML:2.0:cm:bearer">
                <saml:SubjectConfirmationData
                ${IN_RESPONSE_TO}
                NotOnOrAfter="${NOT_ON_OR_AFTER}" Recipient="${ACS_URL}"></saml:SubjectConfirmationData>
            </saml:SubjectConfirmation>
        </saml:Subject>
    """


class AssertionTemplate(XmlTemplate):
    def __init__(self, params):
        super().__init__(params)
        self.subject_statement = None
        self.attribute_statement = None

    def generate_xml(self):
        # Check if the subtemplate values are set, allow users to define their own
        if self.subject_statement is None:
            self.subject_statement = SubjectTemplate(self.params).xml
        if self.attribute_statement is None:
            self.attribute_statement = AttributeStatementTemplate(self.params).xml
        return self.generate_assertion_xml()

    def generate_assertion_xml(self):
        raise NotImplementedError

    def add_signature(self, signature: ET.Element):
        raise NotImplementedError


class ResponseTemplate(XmlTemplate):
    namespace = 'samlp'

    def __init__(self, params, assertion):
        super().__init__(params)
        self.assertion = assertion

    def generate_xml(self):
        return self.element('Response', attrs={
            'Destination': self.params['ACS_URL'],
            'ID': self.params['RESPONSE_ID'],
            'InResponseTo': self.params.get('IN_RESPONSE_TO', None),
            'IssueInstant': self.params['ISSUE_INSTANT'],
            'Version': '2.0',
        }, children=[
            self._get_issuer(),
            self._get_status(),
            self.assertion,
        ])

    def add_signature(self, signature_xml):
        self.xml.insert(1, signature_xml)

    def _get_issuer(self):
        namespace = self.NS_MAP['saml']
        return self.element('Issuer', namespace=namespace, text=self.params['ISSUER'])

    def _get_status(self):
        return self.element('Status', children=[
            self.element('StatusCode', attrs={
                'Value': 'urn:oasis:names:tc:SAML:2.0:status:Success',
            }),
        ])

    """
    # Minimal response:
        <samlp:Response xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol"
                        Destination="${ACS_URL}"
                        ID="${RESPONSE_ID}"
                        ${IN_RESPONSE_TO}
                        IssueInstant="${ISSUE_INSTANT}"
                        Version="2.0">
            <saml:Issuer xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion">${ISSUER}</saml:Issuer>
            ${RESPONSE_SIGNATURE}
            <samlp:Status>
                <samlp:StatusCode Value="urn:oasis:names:tc:SAML:2.0:status:Success"></samlp:StatusCode>
            </samlp:Status>
            ${ASSERTION}
        </samlp:Response>
    """
