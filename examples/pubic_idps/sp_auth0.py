#!/usr/bin/env python3
from flask import Flask, url_for

from flask_saml2.sp import ServiceProvider
from tests.idp.base import CERTIFICATE as IDP_CERTIFICATE
from tests.sp.base import CERTIFICATE, PRIVATE_KEY
from flask_saml2.utils import certificate_from_string
from flask_saml2.signing import RsaSha256Signer, Sha256Digester

# SSO Authentication with auth0.com by Okta

class Auth0ServiceProvider(ServiceProvider):
    def get_logout_return_url(self):
        return url_for('index', _external=True)

    def get_default_login_return_url(self):
        return url_for('index', _external=True)

    def get_sp_digester(self):
        return Sha256Digester()

    def get_sp_signer(self):
        private_key = self.get_sp_private_key()
        return RsaSha256Signer(private_key)

sp = Auth0ServiceProvider()

app = Flask(__name__)
app.debug = True
app.secret_key = 'not a secret'

app.config['SERVER_NAME'] = 'localhost:9000'
app.config['SAML2_SP'] = {
    'certificate': CERTIFICATE,
    'private_key': PRIVATE_KEY,
}

app.config['SAML2_IDENTITY_PROVIDERS'] = [
    {
        'CLASS': 'flask_saml2.sp.idphandler.IdPHandler',
        'OPTIONS': {
            'entity_id': 'urn:tenant-name.us.auth0.com',
            'display_name': 'Auth0',
            'sso_url': 'https://tenant-name.us.auth0.com/samlp/client-id',
            'slo_url': 'https://tenant-name.us.auth0.com/samlp/client-id/logout',
            'certificate': certificate_from_string("""-----BEGIN CERTIFICATE-----
MIIDDTCCAfWgAwIBAgIJIkILTdI4FfT7MA0GCSqGSIb3DQEBCwUAMCQxIjAgBgNVBAMTGWRldi1sbnFxYW84dy51cy5hdXRoMC5jb20wHhcNMjIwNjI5MTM0OTAzWhcNMzYwMzA3MTM0OTAzWjAkMSIwIAYDVQQDExlkZXYtbG5xcWFvOHcudXMuYXV0aDAuY29tMIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA7STwpnPElCxpu+2TJXHisdhKsjeuEVHzd78qf7tqKcMYMgvWhUI7KC97bzqXz/6qEOQ2Odj8ml47TMBXhHI2xV47sIGpyFIFJCc6nIDfMLy7gtcl8LtcVrRNnHe73Ca78BGt//IgtXy/zGhjRGvi4NUXQfDBZN6EUfBq4IpnyZx4WwcpHcJ07Z0O0yDBqClzOQ3L/OA36BPAAHu62MXwzW5biO5e9rznL8PRKFBhp7sCAVhoAF1FKhxClgn73fHJeqPzPEUj3Tv6L3EcT+8dXzWTDJ4Kn7xEzT5q9Nu2fzXKEzaknL1aSIRMyS6CDGW6fsPmbXZEvZtbSw2pyeANhwIDAQABo0IwQDAPBgNVHRMBAf8EBTADAQH/MB0GA1UdDgQWBBQsP9+aD1jB4aJ85PuhVpkATlSOpDAOBgNVHQ8BAf8EBAMCAoQwDQYJKoZIhvcNAQELBQADggEBAM5n21unjdH6EbC1D/1UaVDcoyiZ5euuUtZPAWBRngV/2j4klKZ6fZj9UAO+l5Ae3mtCC/iE5GDFtpFJt9AJsRApxz6qAKdxcRUpnOa4PMsFGLVmgILbE4U6dR9ojvy26T5p6TvMhYs6lDdC78vzlnUu4zg7OrugorhfQ/uy6WvB9cnZR/EBu4psg4lZuOaJwkDdAxX5zt8lwpEOQMhFQYBJbuU2pbHkAGCGu2JLfRKckpYL5vzs6nBfKnmO+OBuEtrRykrmQXHdZcmZE6wUGaiu/5Nl43pPAb/PsXBIkL7v09c6qSRrXFO7ukXctqzsYa6N+rtvRbaE/8HVYmYIMoM=
-----END CERTIFICATE-----"""),
        },
    },
]


@app.route('/')
def index():
    if sp.is_user_logged_in():
        auth_data = sp.get_auth_data_in_session()

        message = f'''
        <p>You are logged in as <strong>{auth_data.nameid}</strong>.
        The IdP sent back the following attributes:<p>
        '''

        attrs = '<dl>{}</dl>'.format(''.join(
            f'<dt>{attr}</dt><dd>{value}</dd>'
            for attr, value in auth_data.attributes.items()))

        logout_url = url_for('flask_saml2_sp.logout')
        logout = f'<form action="{logout_url}" method="POST"><input type="submit" value="Log out"></form>'

        return message + attrs + logout
    else:
        message = '<p>You are logged out.</p>'

        login_url = url_for('flask_saml2_sp.login')
        link = f'<p><a href="{login_url}">Log in to continue</a></p>'

        return message + link


app.register_blueprint(sp.create_blueprint(), url_prefix='/saml/')


if __name__ == '__main__':
    app.run(host='0.0.0.0', port=9000)
