"""
Tests for the Google Apps processor.
"""
# local imports:
from .. import codex
import base

SAML_REQUEST = codex.deflate_and_base64_encode(
    '<?xml version="1.0" encoding="UTF-8"?>'
    '<samlp:AuthnRequest xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol" '
    'ID="doljiidhacjcjifebimhedigpeejhpifpdmlbjai" Version="2.0" '
    'IssueInstant="2011-10-05T17:49:29Z" '
    'ProtocolBinding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST" '
    'ProviderName="google.com" IsPassive="false" '
    'AssertionConsumerServiceURL="https://www.google.com/a/example.com/acs">'
    '<saml:Issuer xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion">'
    'google.com</saml:Issuer>'
    '<samlp:NameIDPolicy AllowCreate="true" '
    'Format="urn:oasis:names:tc:SAML:1.1:nameid-format:unspecified" />'
    '</samlp:AuthnRequest>'
    )
RELAY_STATE = (
    'https://www.google.com/a/example.com/ServiceLogin'
    '?service=writely&passive=true'
    '&continue=https%3A%2F%2Fdocs.google.com%2Fa%2Fexample.com%2F'
    '&followup=https%3A%2F%2Fdocs.google.com%2Fa%2Fexample.com%2F'
    '&ltmpl=homepage'
    )
REQUEST_DATA = {
    'SAMLRequest': SAML_REQUEST,
    'RelayState': RELAY_STATE,
}
GOOGLE_APPS_ACS = 'https://www.google.com/a/example.com/acs'

class TestGoogleAppsProcessor(base.TestBaseProcessor):
    SP_CONFIG = {
        'acs_url': GOOGLE_APPS_ACS,
        'processor': 'saml2idp.google_apps.Processor',
    }
    REQUEST_DATA = REQUEST_DATA
