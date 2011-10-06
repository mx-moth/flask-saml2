"""
Tests for basic view functionality only.

NOTE: These classes do not test anything SAML-related.
Testing actual SAML functionality requires implementation-specific details,
which should be put in another test module.
"""
from django.http import HttpResponseRedirect
from django.contrib.auth.models import User
from django.test import TestCase
from django.test.client import Client
from .. import exceptions


SAML_REQUEST = 'this is not a real SAML Request'
RELAY_STATE = 'abcdefghi0123456789'
REQUEST_DATA = {
    'SAMLRequest': SAML_REQUEST,
    'RelayState': RELAY_STATE,
}


class TestLoginView(TestCase):
    def test_empty_get(self):
        """
        GET request without SAMLResponse data should have failed.
        """
        self.assertRaises(KeyError, lambda : self.client.get('/idp/login/'))

    def test_empty_post(self):
        """
        POST request without SAMLResponse data should have failed.
        """
        self.assertRaises(KeyError, lambda : self.client.post('/idp/login/'))

    def _test_pre_redirect(self):
        self.assertFalse(self.client.session.has_key('SAMLRequest'))
        self.assertFalse(self.client.session.has_key('RelayState'))

    def _test_redirect(self, response):
        self.assertEquals(response.status_code, HttpResponseRedirect.status_code)
        self.assertTrue(response['location'].endswith('/idp/login/process/'))
        self.assertEqual(self.client.session['SAMLRequest'], SAML_REQUEST)
        self.assertEqual(self.client.session['RelayState'], RELAY_STATE)

    def test_get(self):
        """
        GET did not redirect to process URL.
        """
        self._test_pre_redirect()
        response = self.client.get('/idp/login/', data=REQUEST_DATA)
        self._test_redirect(response)

    def test_post(self):
        """
        POST did not redirect to process URL.
        """
        self._test_pre_redirect()
        response = self.client.post('/idp/login/', data=REQUEST_DATA)
        self._test_redirect(response)


class TestLoginProcessView(TestCase):

    def test_process_request_not_authorized(self):
        """
        Bogus request should have triggered exception.
        """

        # Arrange: login new user and setup session variables.
        fred = User.objects.create_user('fred', email='fred@example.com', password='secret')
        self.client.login(username='fred', password='secret')
        session = self.client.session
        session['RelayState'] = RELAY_STATE
        session['SAMLRequest'] = SAML_REQUEST
        session.save()

        # Act and assert:
        func = lambda : self.client.get('/idp/login/process/')
        self.assertRaises(exceptions.CannotHandleAssertion, func)

class TestLogoutView(TestCase):
    def test_logout(self):
        """
        Response did not say logged out.
        """
        response = self.client.get('/idp/logout/')
        self.assertContains(response, 'logged out', status_code=200)

    def test_logout_user(self):
        """
        User account not logged out.
        """
        fred = User.objects.create_user('fred', email='fred@example.com', password='secret')
        self.client.login(username='fred', password='secret')
        self.assertTrue('_auth_user_id' in self.client.session, 'Did not login test user; test is broken.')
        response = self.client.get('/idp/logout/')
        self.assertTrue('_auth_user_id' not in self.client.session, 'Did not logout test user.')
