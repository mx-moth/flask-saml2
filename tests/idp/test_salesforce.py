"""
Tests for the SalesForce Service Provider handler.
"""
import base64

from lxml import etree

from flask_saml2.signing import RsaSha1Signer, Sha1Digester, SignatureTemplate
from flask_saml2.utils import certificate_from_file, private_key_from_file

from . import base

# Normally, the Salesforce private key would only be known by Salesforce. As we
# are generating and signing a request as if it was from Salesforce, we need
# the private key.
SALESFORCE_CERTIFICATE = certificate_from_file(base.KEY_DIR / 'salesforce-certificate.pem')
SALESFORCE_PRIVATE_KEY = private_key_from_file(base.KEY_DIR / 'salesforce-private-key.pem')

RELAY_STATE = '/home/home.jsp'
SALESFORCE_ACS = 'https://login.salesforce.com'


class TestSalesForceSPHandler(base.BaseSPHandlerTests):

    @classmethod
    def setup_class(cls):
        request_id = '_ABC123_some_assertion_id'
        request_xml = etree.fromstring(
            '<samlp:AuthnRequest '
            'xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol" '
            'AssertionConsumerServiceURL="https://login.salesforce.com" '
            'Destination="http://127.0.0.1:8000/+saml" '
            'ID="' + request_id + '" '
            'IssueInstant="2011-10-05T18:49:49.068Z" '
            'ProtocolBinding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST" '
            'Version="2.0">'
            '<saml:Issuer xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion">'
            'https://saml.salesforce.com'
            '</saml:Issuer>'
            '</samlp:AuthnRequest>'
        )

        digester = Sha1Digester()
        signer = RsaSha1Signer(SALESFORCE_PRIVATE_KEY)

        signature = SignatureTemplate.sign(
            base.c14n(request_xml).decode('utf-8'),
            SALESFORCE_CERTIFICATE, digester, signer, request_id)
        request_xml.insert(1, signature.xml)

        cls.REQUEST_DATA = {
            'SAMLRequest': base64.b64encode(base.c14n(request_xml)).decode('utf-8'),
            'RelayState': RELAY_STATE,
        }

    ACS_URL = SALESFORCE_ACS

    SP_CONFIG = [{
        'CLASS': 'flask_saml2.idp.sp.salesforce.SalesforceSPHandler',
        'OPTIONS': {
            'entity_id': 'https://saml.salesforce.com',
            'acs_url': SALESFORCE_ACS,
            'certificate': SALESFORCE_CERTIFICATE,
        },
    }]
