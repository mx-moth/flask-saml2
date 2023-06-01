#!/usr/bin/env python3
from flask import Flask, url_for

from flask_saml2.sp import ServiceProvider, IdPHandler, AuthData
from tests.idp.base import CERTIFICATE as IDP_CERTIFICATE
from tests.sp.base import CERTIFICATE, PRIVATE_KEY
from flask_saml2.utils import certificate_from_string, certificate_from_file, private_key_from_file
from flask_saml2.signing import RsaSha256Signer, Sha256Digester

# How to configure IdP https://learn.microsoft.com/en-gb/azure/active-directory/saas-apps/saml-toolkit-tutorial

class AzureServiceProvider(ServiceProvider):
    def get_logout_return_url(self):
        print (url_for('index', _external=True))
        return url_for('index', _external=True)

    def get_default_login_return_url(self):
        print (url_for('index', _external=True))
        return url_for('index', _external=True)

    def get_sp_digester(self):
        return Sha256Digester()

    def get_sp_signer(self):
        private_key = self.get_sp_private_key()
        return RsaSha256Signer(private_key)

    def get_sp_entity_id(self):
        return "your-application-id-from-azure" #Application ID

class AzureIdPHandler(IdPHandler):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)

    def get_auth_data(self, response) -> AuthData:

        #Skip validating data?

        return AuthData(
            handler=self,
            nameid=response.nameid,
            nameid_format=response.nameid_format,
            attributes=response.attributes,
        )

sp = AzureServiceProvider()

app = Flask(__name__)
app.debug = True
app.secret_key = 'fhu6b4WtvgDxvt8PWsu'

app.config['SERVER_NAME'] = 'localhost:9000'
app.config['SAML2_SP'] = {
    #Generate with openssl req -x509 -sha256 -nodes -days 365 -newkey rsa:4096 -keyout privateKey.key -out certificate.crt
    'certificate': certificate_from_file("examples/pubic_idps/certificate.crt"),
    'private_key': private_key_from_file("examples/pubic_idps/privateKey.key"),
}

tenant_id = 'your-tenant-id-from-azure'

app.config['SAML2_IDENTITY_PROVIDERS'] = [
    {
        'CLASS': 'examples.public_idps.sp_azure.AzureIdPHandler',
        'OPTIONS': {
            'entity_id': 'https://my.domain.com', #Same as you specified on azure
            'display_name': 'Azure AD',
            'sso_url': 'https://login.microsoftonline.com/{}/saml2'.format(tenant_id),
            'slo_url': 'https://login.microsoftonline.com/{}/saml2'.format(tenant_id),
            'certificate': certificate_from_string("""-----BEGIN CERTIFICATE-----
cut-and-paste-saml-certificate-here
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
