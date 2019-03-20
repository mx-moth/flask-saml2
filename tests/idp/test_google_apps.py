"""
Tests for the Google Apps service provider.
"""
import lxml.etree

from flask_saml2 import codex

from . import base

SAML_REQUEST = codex.deflate_and_base64_encode(
    '<?xml version="1.0" encoding="UTF-8"?>'
    '<samlp:AuthnRequest xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol" '
    'ID="doljiidhacjcjifebimhedigpeejhpifpdmlbjai" Version="2.0" '
    'IssueInstant="2011-10-05T17:49:29Z" '
    'ProtocolBinding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST" '
    'ProviderName="google.com" IsPassive="false" '
    'AssertionConsumerServiceURL="https://www.google.com/a/example.com/acs">'
    '<saml:Issuer xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion">'
    'google.com</saml:Issuer>'
    '<samlp:NameIDPolicy AllowCreate="true" '
    'Format="urn:oasis:names:tc:SAML:1.1:nameid-format:unspecified" />'
    '</samlp:AuthnRequest>'
)
RELAY_STATE = (
    'https://www.google.com/a/example.com/ServiceLogin'
    '?service=writely&passive=true'
    '&continue=https%3A%2F%2Fdocs.google.com%2Fa%2Fexample.com%2F'
    '&followup=https%3A%2F%2Fdocs.google.com%2Fa%2Fexample.com%2F'
    '&ltmpl=homepage'
)
GOOGLE_APPS_ACS = 'https://www.google.com/a/example.com/acs'


class TestGoogleAppsSPHandler(base.BaseSPHandlerTests):
    ACS_URL = GOOGLE_APPS_ACS

    SP_CONFIG = [('google_apps', {
        'CLASS': 'flask_saml2.idp.sp.google_apps.GoogleAppsSPHandler',
        'OPTIONS': {
            'entity_id': 'google.com',
            'acs_url': GOOGLE_APPS_ACS,
        },
    })]

    REQUEST_DATA = {
        'SAMLRequest': SAML_REQUEST.decode('utf-8'),
        'RelayState': RELAY_STATE,
    }

    BAD_ACS_URLS = [
        'https://example.com/',
        'https://malicious.com/www.google.com/a/example.com/acs/',
    ]

    def test_authnrequest_bad_acs_url(self):
        for new_acs_url in self.BAD_ACS_URLS:
            self.login(self.user)

            original_request = self.REQUEST_DATA['SAMLRequest']
            xml = lxml.etree.fromstring(codex.decode_saml_xml(original_request))
            xml.set('AssertionConsumerServiceURL', new_acs_url)
            new_request = codex.deflate_and_base64_encode(base.c14n(xml)).decode('utf-8')

            with self.client.session_transaction() as sess:
                sess.update({
                    **self.REQUEST_DATA,
                    'SAMLRequest': new_request,
                })

            response = self.client.get(self.login_process_url)
            assert response.status_code == 400
