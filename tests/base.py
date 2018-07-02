"""
Tests for the Base Processor class.
"""
import urllib.parse
from pathlib import Path

import attr
import flask
from bs4 import BeautifulSoup
from flask import Flask, abort, redirect, url_for

from flask_saml2_idp import adaptor, codex, create_blueprint
from flask_saml2_idp.utils import certificate_from_file, private_key_from_file


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


KEY_DIR = Path(__file__).parent / 'keys' / 'sample'
CERTIFICATE_FILE = KEY_DIR / 'sample-certificate.pem'
PRIVATE_KEY_FILE = KEY_DIR / 'sample-private-key.pem'

CERTIFICATE = certificate_from_file(CERTIFICATE_FILE)
PRIVATE_KEY = private_key_from_file(PRIVATE_KEY_FILE)


class Adaptor(adaptor.Adaptor):

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
            'signing': True,
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


def create_test_app(adaptor):
    app = Flask(__name__)

    app.config['SERVER_NAME'] = 'idp.example.com'
    app.debug = True
    app.testing = True

    app.secret_key = 'not a secret'

    app.register_blueprint(create_blueprint(adaptor))

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
        ('demoSpConfig', {
            'PROCESSOR': 'flask_saml2_idp.sp.demo.Processor',
            'OPTIONS': {
                'acs_url': 'http://127.0.0.1:9000/sp/acs/',
            },
        }),
        ('attrSpConfig', {
            'PROCESSOR': 'flask_saml2_idp.sp.demo.AttributeProcessor',
            'OPTIONS': {
                'acs_url': 'http://127.0.0.1:9000/sp/acs/',
            },
        }),
    ]

    def setup_method(self, method):
        self.adaptor = Adaptor(self.SP_CONFIG)
        self.app = create_test_app(self.adaptor)
        self.client = self.app.test_client()
        self.context = self.app.app_context()
        self.context.push()

    def teardown_method(self, method):
        self.context.pop()

    def add_user(self, user):
        self.adaptor.users.append(user)

    def login(self, user):
        self.adaptor.add_user(user)
        with self.client.session_transaction() as session:
            session['user'] = user.username

    def hit_saml_view(self, url, **kwargs):
        """
        Logs in the test user, then hits a view. Returns a :class:`SamlView`.
        """
        self.login(self.user)
        response = self.client.get(url, **kwargs, follow_redirects=True)

        html = response.data.decode('utf-8')
        soup = BeautifulSoup(html, "html5lib")

        inputtag = soup.findAll('input', {'name': 'SAMLResponse'})[0]
        encoded_response = inputtag['value']
        saml = codex.base64.b64decode(encoded_response)
        saml_soup = BeautifulSoup(saml, "lxml-xml")

        return SamlView(html=html, html_soup=soup, saml=saml, saml_soup=saml_soup)


class BaseProcessorTests(SamlTestCase):
    """
    Sub-classes must provide these class properties:
    SP_CONFIG = ServicePoint metadata settings to use.
    REQUEST_DATA = dictionary containing 'SAMLRequest' and 'RelayState' keys.
    """

    user = User('fred', 'fred@example.com')

    def setup_method(self, method):
        super().setup_method(method)
        self.login_begin_url = url_for('flask_saml2_idp.saml_login_begin')

    def test_authnrequest_handled(self):
        response = self.client.get(
            self.login_begin_url, query_string=self.REQUEST_DATA)
        assert response.status_code == 302

    def test_user_logged_in(self):
        response = self.hit_saml_view(
            self.login_begin_url, query_string=self.REQUEST_DATA)
        assert self.EMAIL in response.saml.decode('utf-8')
