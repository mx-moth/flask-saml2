"""
XML templates for SAML 2.0 IdP
"""
from flask_saml2.types import XmlNode
from flask_saml2.xml_templates import NameIDTemplate, XmlTemplate


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
        return NameIDTemplate(self.params).xml

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

    def add_signature(self, signature: XmlNode):
        raise NotImplementedError


class ResponseTemplate(XmlTemplate):
    namespace = 'samlp'

    def __init__(self, params, assertion_xml: XmlNode):
        super().__init__(params)
        self.assertion_xml = assertion_xml

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
            self.assertion_xml,
        ])

    def add_signature(self, signature_xml: XmlNode) -> XmlNode:
        self.xml.insert(1, signature_xml)

    def _get_issuer(self) -> XmlNode:
        namespace = self.get_namespace_map()['saml']
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
            <samlp:Status>
                <samlp:StatusCode Value="urn:oasis:names:tc:SAML:2.0:status:Success"></samlp:StatusCode>
            </samlp:Status>
            ${ASSERTION}
        </samlp:Response>
    """
