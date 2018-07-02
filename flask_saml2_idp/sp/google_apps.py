import urllib.parse
from functools import partial

from flask_saml2_idp import (
    codex, exceptions, processor, xml_render, xml_templates)


class GoogleAppsProcessor(processor.Processor):
    """
    SalesForce.com-specific SAML 2.0 AuthnRequest to Response Handler Processor.
    """
    def decode_request(self):
        """
        Decodes request using both Base64 and Zipping.
        """
        self.request_xml = codex.decode_base64_and_inflate(self.saml_request)

    def validate_request(self):
        url = urllib.parse.urlparse(self.request_params['ACS_URL'])
        is_valid = url.netloc.endswith('.google.com') \
            and url.path.startswith('/a/') \
            and url.scheme in ('http', 'https')

        if not is_valid:
            raise exceptions.CannotHandleAssertion('AssertionConsumerService is not a Google Apps URL.')

    def format_assertion(self):
        self.assertion_xml = get_assertion_xml(
            parameters=self.assertion_params, signed=True,
            certificate=self.adaptor.get_idp_certificate(),
            private_key=self.adaptor.get_idp_private_key())


class GoogleAppsAssertionTemplate(xml_templates.AssertionTemplate):
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
            self.attribute_statement,  # This might be empty
        ])

    def _get_conditions(self):
        return self.element('Conditions', attrs={
            'NotBefore': self.params['NOT_BEFORE'],
            'NotOnOrAfter': self.params['NOT_ON_OR_AFTER'],
        })

    def _get_authn_context(self):
        return self.element('AuthnStatement', attrs={
            'AuthnInstant': self.params['AUTH_INSTANT'],
        }, children=[
            self.element('AuthnContext', children=[
                self.element('AuthnContextClassRef', text='urn:oasis:names:tc:SAML:2.0:ac:classes:Password'),
            ]),
        ])

    def add_signature(self, signature):
        self.xml.insert(1, signature)

    """
    # Minimal assertion for Google Apps:
    ASSERTION_GOOGLE_APPS = (
        '<saml:Assertion xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion" '
                'ID="${ASSERTION_ID}" '
                'IssueInstant="${ISSUE_INSTANT}" '
                'Version="2.0">'
            '<saml:Issuer>${ISSUER}</saml:Issuer>'
            '${ASSERTION_SIGNATURE}'
            '${SUBJECT_STATEMENT}'
            '<saml:Conditions NotBefore="${NOT_BEFORE}" NotOnOrAfter="${NOT_ON_OR_AFTER}">'
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
    GoogleAppsAssertionTemplate)
