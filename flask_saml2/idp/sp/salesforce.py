import urllib.parse
from functools import partial

from flask_saml2 import exceptions
from flask_saml2.idp import sphandler, xml_render, xml_templates
from flask_saml2.xml_templates import XmlTemplate


class SalesforceSPHandler(sphandler.SPHandler):
    """
    SalesForce.com-specific SAML 2.0 AuthnRequest to Response Handler SPHandler.
    """
    def validate_request(self, request):
        url = urllib.parse.urlparse(request.acs_url)

        is_valid = url.netloc.endswith('.salesforce.com') and \
            url.scheme in ('http', 'https')

        if not is_valid:
            raise exceptions.CannotHandleAssertion('AssertionConsumerService is not a SalesForce URL.')

    def get_audience(self, request):
        return 'https://saml.salesforce.com'

    def format_assertion(self, assertion_params: dict) -> XmlTemplate:
        return get_assertion_xml(
            parameters=assertion_params,
            certificate=self.idp.get_idp_certificate(),
            signer=self.idp.get_idp_signer(),
            digester=self.idp.get_idp_digester())


class SalesforceAssertionTemplate(xml_templates.AssertionTemplate):
    namespace = 'saml'

    def generate_assertion_xml(self):
        return self.element('Assertion', attrs={
            'ID': self.params['ASSERTION_ID'],
            'IssueInstant': self.params['ISSUE_INSTANT'],
            'Version': '2.0',
        }, children=[
            self.element('Issuer', text=self.params['ISSUER']),
            self.subject_statement,
            self._get_conditions(),
            self._get_authn_context(),
            self.attribute_statement,
        ])

    def _get_conditions(self):
        return self.element('Conditions', attrs={
            'NotBefore': self.params['NOT_BEFORE'],
            'NotOnOrAfter': self.params['NOT_ON_OR_AFTER'],
        }, children=[
            self.element('AudienceRestriction', children=[
                self.element('Audience', text=self.params['AUDIENCE']),
            ]),
        ])

    def _get_authn_context(self):
        return self.element('AuthnStatement', attrs={
            'AuthnInstant': self.params['AUTH_INSTANT'],
        }, children=[
            self.element('AuthnContext', children=[
                self.element('AuthnContextClassRef', text='urn:oasis:names:tc:SAML:2.0:ac:classes:Password'),
            ])
        ])

    def add_signature(self, signature):
        self.xml.insert(1, signature)

    """
    # Minimal assertion for SalesForce:
    ASSERTION_SALESFORCE = (
        '<saml:Assertion xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion" '
                'ID="${ASSERTION_ID}" '
                'IssueInstant="${ISSUE_INSTANT}" '
                'Version="2.0">'
            '<saml:Issuer>${ISSUER}</saml:Issuer>'
            '${ASSERTION_SIGNATURE}'
            '${SUBJECT_STATEMENT}'
            '<saml:Conditions NotBefore="${NOT_BEFORE}" NotOnOrAfter="${NOT_ON_OR_AFTER}">'
                '<saml:AudienceRestriction>'
                    '<saml:Audience>${AUDIENCE}</saml:Audience>'
                '</saml:AudienceRestriction>'
            '</saml:Conditions>'
            '<saml:AuthnStatement AuthnInstant="${AUTH_INSTANT}"'
                '>'
                '<saml:AuthnContext>'
                    '<saml:AuthnContextClassRef>urn:oasis:names:tc:SAML:2.0:ac:classes:Password</saml:AuthnContextClassRef>'
                '</saml:AuthnContext>'
            '</saml:AuthnStatement>'
            '${ATTRIBUTE_STATEMENT}'
        '</saml:Assertion>'
    )
    """


get_assertion_xml = partial(
    xml_render.get_assertion_xml,
    SalesforceAssertionTemplate)
