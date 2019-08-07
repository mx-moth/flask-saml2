"""
XML templates for SAML 2.0 IdP
"""
from flask_saml2.signing import SignableTemplate
from flask_saml2.types import XmlNode
from flask_saml2.xml_templates import NameIDTemplate, XmlTemplate


class AttributeTemplate(XmlTemplate):
    """
    .. code-block:: xml

        <saml:Attribute Name="${ATTRIBUTE_NAME}" NameFormat="urn:oasis:names:tc:SAML:2.0:attrname-format:basic">
            <saml:AttributeValue>
                ${ATTRIBUTE_VALUE}
            </saml:AttributeValue>
        </saml:Attribute>
    """
    namespace = 'saml'

    def generate_xml(self):
        return self.element('Attribute', attrs={
            'Name': self.params['ATTRIBUTE_NAME'],
            'NameFormat': 'urn:oasis:names:tc:SAML:2.0:attrname-format:basic',
        }, children=[
            self.element('AttributeValue', text=self.params['ATTRIBUTE_VALUE']),
        ])


class AttributeStatementTemplate(XmlTemplate):
    """
    .. code-block:: xml

        <saml:AttributeStatement>
            ${ATTRIBUTES}
        </saml:AttributeStatement>
    """
    namespace = 'saml'

    def generate_xml(self):
        attributes = self.params.get('ATTRIBUTES', {})
        if not attributes:
            return None

        return self.element('AttributeStatement', children=[
            AttributeTemplate({'ATTRIBUTE_NAME': name, 'ATTRIBUTE_VALUE': value}).xml
            for name, value in attributes.items()
        ])


class SubjectTemplate(XmlTemplate):
    """
    .. code-block:: xml

        <saml:Subject>
            <saml:NameID Format="${SUBJECT_FORMAT}" SPNameQualifier="${SP_NAME_QUALIFIER}">
            ${SUBJECT}
            </saml:NameID>
            <saml:SubjectConfirmation Method="urn:oasis:names:tc:SAML:2.0:cm:bearer">
                <saml:SubjectConfirmationData
                    InResponseTo="${IN_RESPONSE_TO}"
                    NotOnOrAfter="${NOT_ON_OR_AFTER}"
                    Recipient="${ACS_URL}">
                </saml:SubjectConfirmationData>
            </saml:SubjectConfirmation>
        </saml:Subject>
    """
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
            'InResponseTo': self.params['IN_RESPONSE_TO'],
        }

        return self.element('SubjectConfirmation', attrs={
            'Method': 'urn:oasis:names:tc:SAML:2.0:cm:bearer',
        }, children=[
            self.element('SubjectConfirmationData', attrs=scd_attributes),
        ])


class AssertionTemplate(SignableTemplate):
    """
    .. code-block:: xml

        <saml:Assertion xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion"
                ID="${ASSERTION_ID}"
                IssueInstant="${ISSUE_INSTANT}"
                Version="2.0">
            <saml:Issuer>${ISSUER}</saml:Issuer>
            ${ASSERTION_SIGNATURE}
            ${SUBJECT_STATEMENT}
            <saml:Conditions NotBefore="${NOT_BEFORE}" NotOnOrAfter="${NOT_ON_OR_AFTER}">
                <saml:AudienceRestriction>
                    <saml:Audience>${AUDIENCE}</saml:Audience>
                </saml:AudienceRestriction>
            </saml:Conditions>
            <saml:AuthnStatement AuthnInstant="${AUTH_INSTANT}">
                <saml:AuthnContext>
                    <saml:AuthnContextClassRef>urn:oasis:names:tc:SAML:2.0:ac:classes:Password</saml:AuthnContextClassRef>
                </saml:AuthnContext>
            </saml:AuthnStatement>
            ${ATTRIBUTE_STATEMENT}
        </saml:Assertion>
    """
    namespace = 'saml'
    id_parameter = 'ASSERTION_ID'

    def generate_xml(self):
        return self.element('Assertion', attrs={
            'ID': self.params['ASSERTION_ID'],
            'IssueInstant': self.params['ISSUE_INSTANT'],
            'Version': '2.0',
        }, children=[
            self.element('Issuer', text=self.params['ISSUER']),
            self._get_subject_statement(),
            self._get_conditions(),
            self._get_authn_context(),
            self._get_attribute_statement(),
        ])

    def _get_subject_statement(self) -> XmlNode:
        return SubjectTemplate(self.params).xml

    def _get_conditions(self) -> XmlNode:
        return self.element('Conditions', attrs={
            'NotBefore': self.params['NOT_BEFORE'],
            'NotOnOrAfter': self.params['NOT_ON_OR_AFTER'],
        }, children=[
            self.element('AudienceRestriction', children=[
                self.element('Audience', text=self.params['AUDIENCE']),
            ]),
        ])

    def _get_authn_context(self) -> XmlNode:
        return self.element('AuthnStatement', attrs={
            'AuthnInstant': self.params['AUTH_INSTANT'],
        }, children=[
            self.element('AuthnContext', children=[
                self.element('AuthnContextClassRef', text='urn:oasis:names:tc:SAML:2.0:ac:classes:Password'),
            ])
        ])

    def _get_attribute_statement(self) -> XmlNode:
        return AttributeStatementTemplate(self.params).xml


class ResponseTemplate(SignableTemplate):
    """
    .. code-block:: xml

        <samlp:Response xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol"
                        Destination="${ACS_URL}"
                        ID="${RESPONSE_ID}"
                        InResponseTo="${IN_RESPONSE_TO}"
                        IssueInstant="${ISSUE_INSTANT}"
                        Version="2.0">
            <saml:Issuer xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion">${ISSUER}</saml:Issuer>
            <samlp:Status>
                <samlp:StatusCode Value="urn:oasis:names:tc:SAML:2.0:status:Success"></samlp:StatusCode>
            </samlp:Status>
            ${ASSERTION}
        </samlp:Response>
    """
    namespace = 'samlp'
    id_parameter = 'RESPONSE_ID'

    def __init__(self, params, assertion: AssertionTemplate):
        super().__init__(params)
        self.assertion = assertion

    def generate_xml(self):
        return self.element('Response', attrs={
            'Destination': self.params['ACS_URL'],
            'ID': self.params['RESPONSE_ID'],
            'InResponseTo': self.params['IN_RESPONSE_TO'],
            'IssueInstant': self.params['ISSUE_INSTANT'],
            'Version': '2.0',
        }, children=[
            self._get_issuer(),
            self._get_status(),
            self.assertion.xml,
        ])

    def _get_issuer(self) -> XmlNode:
        namespace = self.get_namespace_map()['saml']
        return self.element('Issuer', namespace=namespace, text=self.params['ISSUER'])

    def _get_status(self):
        return self.element('Status', children=[
            self.element('StatusCode', attrs={
                'Value': 'urn:oasis:names:tc:SAML:2.0:status:Success',
            }),
        ])
