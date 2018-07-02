"""
Tests for the SalesForce processor.
"""
import base64

from lxml import etree

from flask_saml2.utils import certificate_from_file, private_key_from_file
from flask_saml2.xml_signing import get_signature_xml

from . import base


def c14n(xml):
    """Get the canonical bytes representation of an lxml XML tree."""
    return etree.tostring(xml, method='c14n', exclusive=True)


# Normally, the Salesforce private key would only be known by Salesforce. As we
# are generating and signing a request as if it was from Salesforce, we need
# the private key.
SALESFORCE_CERTIFICATE = certificate_from_file(base.KEY_DIR / 'salesforce-certificate.pem')
SALESFORCE_PRIVATE_KEY = private_key_from_file(base.KEY_DIR / 'salesforce-private-key.pem')

RELAY_STATE = '/home/home.jsp'
SALESFORCE_ACS = 'https://login.salesforce.com'


class TestSalesForceProcessor(base.BaseProcessorTests):

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

        request_xml.insert(1, get_signature_xml(
            SALESFORCE_CERTIFICATE, SALESFORCE_PRIVATE_KEY,
            c14n(request_xml).decode('utf-8'), request_id))

        cls.REQUEST_DATA = {
            'SAMLRequest': base64.b64encode(c14n(request_xml)).decode('utf-8'),
            'RelayState': RELAY_STATE,
        }

    SP_CONFIG = [('salesforce', {
        'PROCESSOR': 'flask_saml2.idp.sp.salesforce.SalesforceProcessor',
        'OPTIONS': {
            'acs_url': SALESFORCE_ACS,
            'x509_cert': SALESFORCE_CERTIFICATE,
        },
    })]
