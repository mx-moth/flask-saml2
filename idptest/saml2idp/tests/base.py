"""
Tests for the Base Processor class.
"""
import base64
from BeautifulSoup import BeautifulSoup
from django.http import HttpResponseRedirect
from django.conf import settings
from django.contrib.auth.models import User
from django.test import TestCase
from .. import codex
from .. import exceptions
from .. import saml2idp_metadata

class TestBaseProcessor(TestCase):
    """
    Sub-classes must provide these class properties:
    SP_CONFIG = ServicePoint metadata settings to use.
    REQUEST_DATA = dictionary containing 'SAMLRequest' and 'RelayState' keys.
    """
    USERNAME = 'fred'
    PASSWORD = 'secret'
    EMAIL = 'fred@example.com'

    def setUp(self):
        fred = User.objects.create_user(self.USERNAME, email=self.EMAIL, password=self.PASSWORD)
        saml2idp_metadata.SAML2IDP_REMOTES['foobar'] = self.SP_CONFIG

    def tearDown(self):
        del saml2idp_metadata.SAML2IDP_REMOTES['foobar']

    def test_authnrequest_handled(self):
        # Arrange/Act:
        response = self.client.get('/idp/login/', data=self.REQUEST_DATA, follow=False)

        # Assert:
        self.assertEqual(response.status_code, 302)

    def test_user_logged_in(self):
        # Arrange: login new user.
        self.client.login(username=self.USERNAME, password=self.PASSWORD)

        # Act:
        response = self.client.get('/idp/login/', data=self.REQUEST_DATA, follow=True)
        soup = BeautifulSoup(response.content)
        inputtag = soup.findAll('input', {'name':'SAMLResponse'})[0]
        encoded_response = inputtag['value']
        samlresponse = codex.base64.b64decode(encoded_response)

        # Assert:
        self.assertTrue(self.EMAIL in samlresponse)
