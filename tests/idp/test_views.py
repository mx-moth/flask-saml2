"""
Tests for basic view functionality only.

NOTE: These classes do not test anything SAML-related.
Testing actual SAML functionality requires implementation-specific details,
which should be put in another test module.
"""
import pytest
from flask import url_for
from lxml import etree
from werkzeug.exceptions import BadRequestKeyError

from flask_saml2.utils import certificate_to_string
from flask_saml2.xml_templates import NAMESPACE_MAP

from .base import CERTIFICATE, SamlTestCase, User

SAML_REQUEST = 'this is not a real SAML Request'
RELAY_STATE = 'abcdefghi0123456789'
REQUEST_DATA = {
    'SAMLRequest': SAML_REQUEST,
    'RelayState': RELAY_STATE,
}


class TestLoginView(SamlTestCase):
    def setup_method(self, method):
        super().setup_method(method)
        self.login_begin_url = url_for('flask_saml2_idp.login_begin', _external=True)
        self.login_process_url = url_for('flask_saml2_idp.login_process', _external=True)

    def test_empty_get(self):
        """GET request without SAMLResponse data should fail."""
        with pytest.raises(BadRequestKeyError):
            self.client.get(self.login_begin_url)

    def test_empty_post(self):
        """POST request without SAMLResponse data should fail."""
        with pytest.raises(BadRequestKeyError):
            self.client.post(self.login_begin_url)

    def _test_pre_redirect(self):
        with self.client.session_transaction() as session:
            assert 'SAMLRequest' not in session
            assert 'RelayState' not in session

    def _test_redirect(self, response, status_code=302):
        assert response.status_code == status_code
        assert response.headers['location'] == self.login_process_url

        with self.client.session_transaction() as session:
            assert session['SAMLRequest'] == SAML_REQUEST
            assert session['RelayState'] == RELAY_STATE

    def test_get(self):
        """
        GET did not redirect to process URL.
        """
        self._test_pre_redirect()
        response = self.client.get(self.login_begin_url, query_string=REQUEST_DATA)
        self._test_redirect(response)

    def test_post(self):
        """
        POST did not redirect to process URL.
        """
        self._test_pre_redirect()
        response = self.client.post(self.login_begin_url, data=REQUEST_DATA)
        self._test_redirect(response)


class TestLoginProcessView(SamlTestCase):
    def test_process_request_not_authorized(self):
        """Bogus request should have triggered exception."""
        self.login(User('jordan', 'jordan@example.com'))

        with self.client.session_transaction() as session:
            session['RelayState'] = RELAY_STATE
            session['SAMLRequest'] = SAML_REQUEST

        response = self.client.get(url_for('flask_saml2_idp.login_process'))
        assert response.status_code == 400


class TestLogoutView(SamlTestCase):
    def test_logout(self):
        """
        Response did not say logged out.
        """
        self.login(User(username='alex', email='alex@example.com'))

        with self.client.session_transaction() as session:
            assert 'user' in session

        response = self.client.get(url_for('flask_saml2_idp.logout'))

        assert response.status_code == 200
        assert 'logged out' in response.data.decode('utf-8')

        with self.client.session_transaction() as session:
            assert 'user' not in session

    def test_logout_redirect(self):
        self.login(User(username='alex', email='alex@example.com'))

        redirect_url = 'https://saml.serviceprovid.er/somewhere/'
        response = self.client.get(
            url_for('flask_saml2_idp.logout'),
            query_string={'redirect_to': redirect_url})

        assert response.status_code == 302
        assert response.headers['Location'] == redirect_url

    def test_logout_redirect_with_invalid_url_fails(self):
        self.login(User(username='alex', email='alex@example.com'))

        redirect_url = '://saml.serviceprovid.er/somewhere/'
        response = self.client.get(
            url_for('flask_saml2_idp.logout'),
            query_string={'redirect_to': redirect_url})

        assert response.status_code == 200
        assert 'logged out' in response.data.decode('utf-8')


class TestMetadataView(SamlTestCase):
    def test_rendering_metadata_view(self):
        xpath = lambda el, path: el.xpath(path, namespaces=NAMESPACE_MAP)[0]

        response = self.client.get(url_for('flask_saml2_idp.metadata'))
        response_xml = etree.fromstring(response.data.decode('utf-8'))

        certificate = certificate_to_string(CERTIFICATE)
        login_url = url_for('flask_saml2_idp.login_begin', _external=True)
        logout_url = url_for('flask_saml2_idp.logout', _external=True)

        idp = xpath(response_xml, '/md:EntityDescriptor/md:IDPSSODescriptor')
        enc_key = xpath(idp, 'md:KeyDescriptor[@use="encryption"]')
        sign_key = xpath(idp, 'md:KeyDescriptor[@use="signing"]')

        assert certificate == xpath(enc_key, './/ds:X509Certificate').text
        assert certificate == xpath(sign_key, './/ds:X509Certificate').text

        assert login_url == xpath(idp, 'md:SingleSignOnService').get('Location')
        assert logout_url == xpath(idp, 'md:SingleLogoutService').get('Location')
