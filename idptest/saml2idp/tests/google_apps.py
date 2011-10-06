"""
Tests for the Google Apps processor.
"""
import base64
from BeautifulSoup import BeautifulSoup
from django.http import HttpResponseRedirect
from django.conf import settings
from django.contrib.auth.models import User
from django.test import TestCase
from .. import codex
from .. import exceptions
from .. import saml2idp_settings

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
REQUEST_DATA = {
    'SAMLRequest': SAML_REQUEST,
    'RelayState': RELAY_STATE,
}
GOOGLE_APPS_ACS = 'https://www.google.com/a/example.com/acs'

FRED_EMAIL = 'fred@example.com'

class TestGoogleAppsProcessor(TestCase):

    def setUp(self):
        fred = User.objects.create_user('fred', email=FRED_EMAIL, password='secret')
        self._old_acs = saml2idp_settings.SAML2IDP_VALID_ACS # save
        saml2idp_settings.SAML2IDP_VALID_ACS = [ GOOGLE_APPS_ACS ]

    def tearDown(self):
        saml2idp_settings.SAML2IDP_VALID_ACS = self._old_acs # restore

    def test_authnrequest_handled(self):
        # Arrange/Act:
        response = self.client.get('/idp/login/', data=REQUEST_DATA, follow=False)

        # Assert:
        self.assertEqual(response.status_code, 302)

    def test_user_logged_in(self):
        # Arrange: login new user.
        self.client.login(username='fred', password='secret')

        # Act:
        response = self.client.get('/idp/login/', data=REQUEST_DATA, follow=True)
        soup = BeautifulSoup(response.content)
        inputtag = soup.findAll('input', {'name':'SAMLResponse'})[0]
        encoded_response = inputtag['value']
        samlresponse = codex.base64.b64decode(encoded_response)

        # Assert:
        self.assertContains(response, '<input type="hidden" name="SAMLResponse"')
        self.assertTrue(FRED_EMAIL in samlresponse)
