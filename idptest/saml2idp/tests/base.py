"""
Tests for the Base Processor class.
"""
import base64
from BeautifulSoup import BeautifulSoup, BeautifulStoneSoup
from django.http import HttpResponseRedirect
from django.conf import settings
from django.contrib.auth.models import User
from django.test import TestCase
from .. import codex
from .. import exceptions
from .. import saml2idp_metadata

class SamlTestCase(TestCase):
    """
    Sub-classes must provide these class properties:
    SP_CONFIG = ServicePoint metadata settings to use.
    """
    BAD_VALUE = '!BAD VALUE!'
    USERNAME = 'fred'
    PASSWORD = 'secret'
    EMAIL = 'fred@example.com'

    def setUp(self):
        fred = User.objects.create_user(self.USERNAME, email=self.EMAIL, password=self.PASSWORD)
        saml2idp_metadata.SAML2IDP_REMOTES['foobar'] = self.SP_CONFIG

    def tearDown(self):
        del saml2idp_metadata.SAML2IDP_REMOTES['foobar']


    def _hit_saml_view(self, url, data={}):
        """
        Logs in the test user, then hits a view.
        Sets the self._html, self._html_soup, self._saml and self._saml_soup
        properties, which can be used in assert statements.
        """
        # Reset them all to a known BAD_VALUE, so we don't have to guess.
        self._html = self.BAD_VALUE
        self._html_soup = self.BAD_VALUE
        self._saml = self.BAD_VALUE
        self._saml_soup = self.BAD_VALUE

        # Arrange: login new user.
        self.client.login(username=self.USERNAME, password=self.PASSWORD)

        # Act:
        response = self.client.get(url, data=data, follow=True)
        html = response.content
        soup = BeautifulSoup(html)
        inputtag = soup.findAll('input', {'name':'SAMLResponse'})[0]
        encoded_response = inputtag['value']
        saml = codex.base64.b64decode(encoded_response)
        saml_soup = BeautifulStoneSoup(saml)

        # Set properties.
        self._html = html
        self._html_soup = soup
        self._saml = saml
        self._saml_soup = saml_soup

        return # not returning anything


class TestBaseProcessor(SamlTestCase):
    """
    Sub-classes must provide these class properties:
    SP_CONFIG = ServicePoint metadata settings to use.
    REQUEST_DATA = dictionary containing 'SAMLRequest' and 'RelayState' keys.
    """
    USERNAME = 'fred'
    PASSWORD = 'secret'
    EMAIL = 'fred@example.com'

    def test_authnrequest_handled(self):
        # Arrange/Act:
        response = self.client.get('/idp/login/', data=self.REQUEST_DATA, follow=False)

        # Assert:
        self.assertEqual(response.status_code, 302)

    def test_user_logged_in(self):
        # Arrange/Act:
        self._hit_saml_view('/idp/login', data=self.REQUEST_DATA)

        # Assert:
        self.assertTrue(self.EMAIL in self._saml)
