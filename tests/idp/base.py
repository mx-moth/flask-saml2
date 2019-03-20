"""
Tests for the Base SPHandler class.
"""
import urllib.parse
from pathlib import Path

import attr
import flask
import lxml.etree
from bs4 import BeautifulSoup
from flask import Flask, abort, redirect, url_for

from flask_saml2 import codex
from flask_saml2.idp import IdentityProvider, create_blueprint
from flask_saml2.utils import certificate_from_file, private_key_from_file


def c14n(xml):
    """Get the canonical bytes representation of an lxml XML tree."""
    return lxml.etree.tostring(xml, method='c14n', exclusive=True)


@attr.s
class User:
    username = attr.ib()
    email = attr.ib()


@attr.s
class SamlView:
    html = attr.ib()
    html_soup = attr.ib()
    saml = attr.ib()
    saml_soup = attr.ib()
    form_action = attr.ib()


KEY_DIR = Path(__file__).parent.parent / 'keys' / 'sample'
CERTIFICATE_FILE = KEY_DIR / 'idp-certificate.pem'
PRIVATE_KEY_FILE = KEY_DIR / 'idp-private-key.pem'

CERTIFICATE = certificate_from_file(CERTIFICATE_FILE)
PRIVATE_KEY = private_key_from_file(PRIVATE_KEY_FILE)


class IdentityProvider(IdentityProvider):

    def __init__(self, service_providers, users=None, **kwargs):
        super().__init__(**kwargs)
        self.service_providers = service_providers
        self.users = {}
        if users is not None:
            for user in users:
                self.add_user(user)

    def get_idp_config(self):
        return {
            'issuer': 'Test IdP',
            'autosubmit': True,
            'certificate': CERTIFICATE,
            'private_key': PRIVATE_KEY,
        }

    def add_user(self, user):
        self.users[user.username] = user

    def get_service_providers(self):
        return self.service_providers

    def login_required(self):
        if not self.is_user_logged_in():
            abort(redirect('http://example.com/login/'))

    def is_user_logged_in(self):
        if 'user' not in flask.session:
            return False

        if flask.session['user'] not in self.users:
            return False

        return True

    def logout(self):
        del flask.session['user']

    def get_current_user(self):
        return self.users[flask.session['user']]

    def is_valid_redirect(self, url):
        url = urllib.parse.urlparse(url)
        return url.scheme == 'https' and url.netloc == 'saml.serviceprovid.er'


def create_test_app(idp: IdentityProvider):
    app = Flask(__name__)

    app.config['SERVER_NAME'] = 'idp.example.com'
    app.debug = True
    app.testing = True

    app.secret_key = 'not a secret'

    app.register_blueprint(create_blueprint(idp))

    return app


class SamlTestCase:
    """
    Sub-classes must provide these class properties:
    SP_CONFIG = ServicePoint metadata settings to use.
    """
    BAD_VALUE = '!BAD VALUE!'
    USERNAME = 'fred'
    PASSWORD = 'secret'
    EMAIL = 'fred@example.com'

    SP_CONFIG = [
        {
            'CLASS': 'flask_saml2.idp.sp.demo.SPHandler',
            'OPTIONS': {
                'entity_id': 'http://example.com/',
                'acs_url': 'http://127.0.0.1:9000/sp/acs/',
            },
        },
        {
            'CLASS': 'flask_saml2.idp.sp.demo.AttributeSPHandler',
            'OPTIONS': {
                'entity_id': 'http://example.com/',
                'acs_url': 'http://127.0.0.1:9000/sp/acs/',
            },
        },
    ]

    def setup_method(self, method):
        self.idp = IdentityProvider(self.SP_CONFIG)
        self.app = create_test_app(self.idp)
        self.client = self.app.test_client()
        self.context = self.app.app_context()
        self.context.push()

    def teardown_method(self, method):
        self.context.pop()

    def add_user(self, user):
        self.idp.users.append(user)

    def login(self, user):
        self.idp.add_user(user)
        with self.client.session_transaction() as session:
            session['user'] = user.username

    def hit_saml_view(self, url, **kwargs):
        """
        Logs in the test user, then hits a view. Returns a :class:`SamlView`.
        """
        self.login(self.user)
        response = self.client.get(url, **kwargs, follow_redirects=True)

        assert response.status_code == 200

        html = response.data.decode('utf-8')
        soup = BeautifulSoup(html, "html5lib")

        form = soup.find('form')
        form_action = form['action']

        inputtag = form.find('input', {'name': 'SAMLResponse'})
        encoded_response = inputtag['value']
        saml = codex.base64.b64decode(encoded_response)
        saml_soup = BeautifulSoup(saml, "lxml-xml")

        return SamlView(
            html=html, html_soup=soup,
            saml=saml, saml_soup=saml_soup,
            form_action=form_action)


class BaseSPHandlerTests(SamlTestCase):
    """
    Sub-classes must provide these class properties:
    SP_CONFIG = ServicePoint metadata settings to use.
    REQUEST_DATA = dictionary containing 'SAMLRequest' and 'RelayState' keys.
    """

    user = User('fred', 'fred@example.com')

    def setup_method(self, method):
        super().setup_method(method)
        self.login_begin_url = url_for('flask_saml2_idp.login_begin')
        self.login_process_url = url_for('flask_saml2_idp.login_process')

    def test_redirected(self):
        response = self.client.get(
            self.login_begin_url, query_string=self.REQUEST_DATA)
        assert response.status_code == 302
        assert response.headers['Location'] == self.login_process_url

    def test_authnrequest_handled(self):
        self.login(self.user)
        with self.client.session_transaction() as sess:
            sess.update(self.REQUEST_DATA)
        response = self.hit_saml_view(self.login_process_url)

        assert response.form_action == self.ACS_URL

    def test_user_logged_in(self):
        response = self.hit_saml_view(
            self.login_begin_url, query_string=self.REQUEST_DATA)
        assert self.EMAIL in response.saml.decode('utf-8')
