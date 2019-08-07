import unittest

import attr
import lxml.etree
from xmlunittest import XmlTestMixin

from flask_saml2.idp.xml_templates import AssertionTemplate, ResponseTemplate
from flask_saml2.signing import RsaSha1Signer, Sha1Digester, SignatureTemplate
from flask_saml2.types import XmlNode
from flask_saml2.utils import (
    certificate_from_file, certificate_from_string, private_key_from_file,
    private_key_from_string)

from .base import (
    CERTIFICATE, CERTIFICATE_FILE, PRIVATE_KEY, PRIVATE_KEY_FILE, c14n)

X509_CERTIFICATE_DATA = """
-----BEGIN CERTIFICATE-----
MIICKzCCAdWgAwIBAgIJAM8DxRNtPj90MA0GCSqGSIb3DQEBBQUAMEUxCzAJBgNVBAYTAkFVMRMwEQYD
VQQIEwpTb21lLVN0YXRlMSEwHwYDVQQKExhJbnRlcm5ldCBXaWRnaXRzIFB0eSBMdGQwHhcNMTEwODEy
MjA1MTIzWhcNMTIwODExMjA1MTIzWjBFMQswCQYDVQQGEwJBVTETMBEGA1UECBMKU29tZS1TdGF0ZTEh
MB8GA1UEChMYSW50ZXJuZXQgV2lkZ2l0cyBQdHkgTHRkMFwwDQYJKoZIhvcNAQEBBQADSwAwSAJBANcN
mgm4YlSUAr2xdWei5aRU/DbWtsQ47gjkv28Ekje3ob+6q0M+D5phwYDcv9ygYmuJ5wOi1cPprsWdFWmv
SusCAwEAAaOBpzCBpDAdBgNVHQ4EFgQUzyBR9+vE8bygqvD6CZ/w6aQPikMwdQYDVR0jBG4wbIAUzyBR
9+vE8bygqvD6CZ/w6aQPikOhSaRHMEUxCzAJBgNVBAYTAkFVMRMwEQYDVQQIEwpTb21lLVN0YXRlMSEw
HwYDVQQKExhJbnRlcm5ldCBXaWRnaXRzIFB0eSBMdGSCCQDPA8UTbT4/dDAMBgNVHRMEBTADAQH/MA0G
CSqGSIb3DQEBBQUAA0EAIQuPLA/mlMJAMF680kL7reX5WgyRwAtRzJK6FgNjE7kRaLZQ79UKYVYa0VAy
rRdoNEyVhG4tJFEiQJzaLWsl/A==
-----END CERTIFICATE-----
""".strip()
X509_CERTIFICATE_INLINE = ''.join(X509_CERTIFICATE_DATA.splitlines()[1:-1])

X509_PRIVATE_KEY_DATA = """
-----BEGIN RSA PRIVATE KEY-----
MIIBPQIBAAJBANcNmgm4YlSUAr2xdWei5aRU/DbWtsQ47gjkv28Ekje3ob+6q0M+D5phwYDcv9ygYmuJ
5wOi1cPprsWdFWmvSusCAwEAAQJBAKQCzZ3oL6YNk+GUO9QkWjtwTUKNkqooOPIzcwR6WgF+9q2vSHi4
1/6fv1Nh2PeOud7/dqqNIKllFewHbrlliuECIQD4voeFjHGL39epeWVTibqzQgPLV3Ziflv30GdovjLh
UwIhAN1TfM8SqvPb2mzUs/jHL2P29uSPulwwoyNCNvtY7kUJAiEA29aALc63F5kIoFaS7+bc48rnUZKG
JXxpybYdfpwCmdMCIQDHFnqGqnwsr+9jRlI9zq7KdTTRlJhGpVmaNc3PeseaQQIhAO9zQE+jPX+jWlhi
Mc3fs9jcbUbJ1jSP6/h0Wwr2oWIG
-----END RSA PRIVATE KEY-----
""".strip()
X509_PRIVATE_KEY_INLINE = ''.join(X509_CERTIFICATE_DATA.splitlines()[1:-1])


@attr.s
class FauxXmlTemplate:
    xml_str: str = attr.ib()

    def get_xml_string(self, *args, **kwargs):
        return c14n(self.xml).decode('utf-8')

    @property
    def xml(self):
        return lxml.etree.fromstring(self.xml_str)


IDP_ISSUER = 'http://127.0.0.1:8000'
IDP_PARAMS = {
    'ISSUER': IDP_ISSUER,
}

ACS_URL = 'https://www.example.net/a/example.com/acs'
REQUEST_ID = 'mpjibjdppiodcpciaefmdahiipjpcghdcfjodkbi'
REQUEST_PARAMS = {
    'ACS_URL': ACS_URL,
    'REQUEST_ID': REQUEST_ID,
}


ASSERTION_ID = '_7ccdda8bc6b328570c03b218d7521772998da45374'
ASSERTION_SALESFORCE_PARAMS = {
    'ASSERTION_ID': ASSERTION_ID,
    'AUDIENCE': 'example.net',
    'AUTH_INSTANT': '2011-08-11T23:38:34Z',
    'ISSUE_INSTANT': '2011-08-11T23:38:34Z',
    'NOT_BEFORE': '2011-08-11T23:38:04Z',
    'NOT_ON_OR_AFTER': '2011-08-11T23:43:34Z',
    'SESSION_NOT_ON_OR_AFTER': '2011-08-12T07:38:34Z',
    'SP_NAME_QUALIFIER': 'example.net',
    'SUBJECT': 'randomuser@example.com',
    'SUBJECT_FORMAT': 'urn:oasis:names:tc:SAML:2.0:nameid-format:email',
}

SIGNATURE_TEMPLATE_STR = (
    f'<ds:Signature xmlns:ds="http://www.w3.org/2000/09/xmldsig#">'
    f'<ds:SignedInfo><ds:CanonicalizationMethod Algorithm="http://www.w3.org/2001/10/xml-exc-c14n#"></ds:CanonicalizationMethod><ds:SignatureMethod Algorithm="http://www.w3.org/2000/09/xmldsig#rsa-sha1"></ds:SignatureMethod><ds:Reference URI="#abcdabcdabcdabcdabcdabcdabcdabcdabcdabcd"><ds:Transforms><ds:Transform Algorithm="http://www.w3.org/2000/09/xmldsig#enveloped-signature"></ds:Transform><ds:Transform Algorithm="http://www.w3.org/2001/10/xml-exc-c14n#"></ds:Transform></ds:Transforms><ds:DigestMethod Algorithm="http://www.w3.org/2000/09/xmldsig#sha1"></ds:DigestMethod><ds:DigestValue>+ia+Gd5r/5P3C8IwhDTkpEC7rQI=</ds:DigestValue></ds:Reference></ds:SignedInfo>'
    f'<ds:SignatureValue>t1IywxEzobY8ZyHL+iuB+E3zzVAWByUjRqFTdyNerGbGSRwo0oYWx6hcYX+ST1DTDaQ50gV2PJeibbykFsA3vQ==</ds:SignatureValue>'
    f'<ds:KeyInfo><ds:X509Data><ds:X509Certificate>{X509_CERTIFICATE_INLINE}</ds:X509Certificate></ds:X509Data></ds:KeyInfo>'
    f'</ds:Signature>'
)

ASSERTION_SALESFORCE_STR = (
    f'<saml:Assertion xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion" ID="{ASSERTION_ID}" IssueInstant="2011-08-11T23:38:34Z" Version="2.0">'
    f'<saml:Issuer>{IDP_ISSUER}</saml:Issuer>'
    f'<saml:Subject><saml:NameID Format="urn:oasis:names:tc:SAML:2.0:nameid-format:email" SPNameQualifier="example.net">randomuser@example.com</saml:NameID><saml:SubjectConfirmation Method="urn:oasis:names:tc:SAML:2.0:cm:bearer"><saml:SubjectConfirmationData InResponseTo="{REQUEST_ID}" NotOnOrAfter="2011-08-11T23:43:34Z" Recipient="{ACS_URL}"></saml:SubjectConfirmationData></saml:SubjectConfirmation></saml:Subject>'
    f'<saml:Conditions NotBefore="2011-08-11T23:38:04Z" NotOnOrAfter="2011-08-11T23:43:34Z"><saml:AudienceRestriction><saml:Audience>example.net</saml:Audience></saml:AudienceRestriction></saml:Conditions>'
    f'<saml:AuthnStatement AuthnInstant="2011-08-11T23:38:34Z"><saml:AuthnContext><saml:AuthnContextClassRef>urn:oasis:names:tc:SAML:2.0:ac:classes:Password</saml:AuthnContextClassRef></saml:AuthnContext></saml:AuthnStatement>'
    f'</saml:Assertion>'
)
ASSERTION_SALESFORCE = FauxXmlTemplate(ASSERTION_SALESFORCE_STR)

SIGNED_ASSERTION_SALESFORCE_STR = (
    f'<saml:Assertion xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion" ID="{ASSERTION_ID}" IssueInstant="2011-08-11T23:38:34Z" Version="2.0">'
    f'<saml:Issuer>{IDP_ISSUER}</saml:Issuer>'
    f'<ds:Signature xmlns:ds="http://www.w3.org/2000/09/xmldsig#"><ds:SignedInfo><ds:CanonicalizationMethod Algorithm="http://www.w3.org/2001/10/xml-exc-c14n#"></ds:CanonicalizationMethod><ds:SignatureMethod Algorithm="http://www.w3.org/2000/09/xmldsig#rsa-sha1"></ds:SignatureMethod><ds:Reference URI="#{ASSERTION_ID}"><ds:Transforms><ds:Transform Algorithm="http://www.w3.org/2000/09/xmldsig#enveloped-signature"></ds:Transform><ds:Transform Algorithm="http://www.w3.org/2001/10/xml-exc-c14n#"></ds:Transform></ds:Transforms><ds:DigestMethod Algorithm="http://www.w3.org/2000/09/xmldsig#sha1"></ds:DigestMethod><ds:DigestValue>b7HwOJQgKYvhWcrUH17T8WXTY24=</ds:DigestValue></ds:Reference></ds:SignedInfo><ds:SignatureValue>WP+9aFiuj52WLW6ebwSaQhF2nU/wtyP3E2dudTa6mVTSjItpqduUqWR3rp/q39Hsehde6i+4RlbGQkZUwZSPEw==</ds:SignatureValue><ds:KeyInfo><ds:X509Data><ds:X509Certificate>{X509_CERTIFICATE_INLINE}</ds:X509Certificate></ds:X509Data></ds:KeyInfo></ds:Signature>'
    f'<saml:Subject><saml:NameID Format="urn:oasis:names:tc:SAML:2.0:nameid-format:email" SPNameQualifier="example.net">randomuser@example.com</saml:NameID><saml:SubjectConfirmation Method="urn:oasis:names:tc:SAML:2.0:cm:bearer"><saml:SubjectConfirmationData InResponseTo="{REQUEST_ID}" NotOnOrAfter="2011-08-11T23:43:34Z" Recipient="{ACS_URL}"></saml:SubjectConfirmationData></saml:SubjectConfirmation></saml:Subject>'
    f'<saml:Conditions NotBefore="2011-08-11T23:38:04Z" NotOnOrAfter="2011-08-11T23:43:34Z"><saml:AudienceRestriction><saml:Audience>example.net</saml:Audience></saml:AudienceRestriction></saml:Conditions>'
    f'<saml:AuthnStatement AuthnInstant="2011-08-11T23:38:34Z"><saml:AuthnContext><saml:AuthnContextClassRef>urn:oasis:names:tc:SAML:2.0:ac:classes:Password</saml:AuthnContextClassRef></saml:AuthnContext></saml:AuthnStatement>'
    f'</saml:Assertion>'
)
SIGNED_ASSERTION_SALESFORCE = FauxXmlTemplate(SIGNED_ASSERTION_SALESFORCE_STR)

RESPONSE_ID = '_2972e82c07bb5453956cc11fb19cad97ed26ff8bb4'
RESPONSE_PARAMS = {
    'ASSERTION': '',
    'ACS_URL': ACS_URL,
    'ISSUE_INSTANT': '2011-08-11T23:38:34Z',
    'NOT_ON_OR_AFTER': '2011-08-11T23:43:34Z',
    'RESPONSE_ID': RESPONSE_ID,
    'SP_NAME_QUALIFIER': 'example.net',
    'SUBJECT': 'randomuser@example.com',
    'SUBJECT_FORMAT': 'urn:oasis:names:tc:SAML:2.0:nameid-format:email',
    'IN_RESPONSE_TO': REQUEST_ID,
}

RESPONSE_XML = (
    f'<samlp:Response xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol" Destination="{ACS_URL}" ID="{RESPONSE_ID}" InResponseTo="{REQUEST_ID}" IssueInstant="2011-08-11T23:38:34Z" Version="2.0">'
    f'<saml:Issuer xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion">{IDP_ISSUER}</saml:Issuer>'
    f'<samlp:Status><samlp:StatusCode Value="urn:oasis:names:tc:SAML:2.0:status:Success"></samlp:StatusCode></samlp:Status>'
    f'<saml:Assertion xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion" ID="{ASSERTION_ID}" IssueInstant="2011-08-11T23:38:34Z" Version="2.0"><saml:Issuer>{IDP_ISSUER}</saml:Issuer><saml:Subject><saml:NameID Format="urn:oasis:names:tc:SAML:2.0:nameid-format:email" SPNameQualifier="example.net">randomuser@example.com</saml:NameID><saml:SubjectConfirmation Method="urn:oasis:names:tc:SAML:2.0:cm:bearer"><saml:SubjectConfirmationData InResponseTo="{REQUEST_ID}" NotOnOrAfter="2011-08-11T23:43:34Z" Recipient="{ACS_URL}"></saml:SubjectConfirmationData></saml:SubjectConfirmation></saml:Subject><saml:Conditions NotBefore="2011-08-11T23:38:04Z" NotOnOrAfter="2011-08-11T23:43:34Z"><saml:AudienceRestriction><saml:Audience>example.net</saml:Audience></saml:AudienceRestriction></saml:Conditions><saml:AuthnStatement AuthnInstant="2011-08-11T23:38:34Z"><saml:AuthnContext><saml:AuthnContextClassRef>urn:oasis:names:tc:SAML:2.0:ac:classes:Password</saml:AuthnContextClassRef></saml:AuthnContext></saml:AuthnStatement></saml:Assertion>'
    f'</samlp:Response>'
)
RESPONSE_WITH_SIGNED_ASSERTION_SALESFORCE_XML = (
    f'<samlp:Response xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol" Destination="{ACS_URL}" ID="{RESPONSE_ID}" InResponseTo="{REQUEST_ID}" IssueInstant="2011-08-11T23:38:34Z" Version="2.0">'
    f'<saml:Issuer xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion">{IDP_ISSUER}</saml:Issuer>'
    f'<samlp:Status><samlp:StatusCode Value="urn:oasis:names:tc:SAML:2.0:status:Success"></samlp:StatusCode></samlp:Status>'
    f'<saml:Assertion xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion" ID="{ASSERTION_ID}" IssueInstant="2011-08-11T23:38:34Z" Version="2.0"><saml:Issuer>{IDP_ISSUER}</saml:Issuer><ds:Signature xmlns:ds="http://www.w3.org/2000/09/xmldsig#"><ds:SignedInfo><ds:CanonicalizationMethod Algorithm="http://www.w3.org/2001/10/xml-exc-c14n#"></ds:CanonicalizationMethod><ds:SignatureMethod Algorithm="http://www.w3.org/2000/09/xmldsig#rsa-sha1"></ds:SignatureMethod><ds:Reference URI="#{ASSERTION_ID}"><ds:Transforms><ds:Transform Algorithm="http://www.w3.org/2000/09/xmldsig#enveloped-signature"></ds:Transform><ds:Transform Algorithm="http://www.w3.org/2001/10/xml-exc-c14n#"></ds:Transform></ds:Transforms><ds:DigestMethod Algorithm="http://www.w3.org/2000/09/xmldsig#sha1"></ds:DigestMethod><ds:DigestValue>b7HwOJQgKYvhWcrUH17T8WXTY24=</ds:DigestValue></ds:Reference></ds:SignedInfo><ds:SignatureValue>WP+9aFiuj52WLW6ebwSaQhF2nU/wtyP3E2dudTa6mVTSjItpqduUqWR3rp/q39Hsehde6i+4RlbGQkZUwZSPEw==</ds:SignatureValue><ds:KeyInfo><ds:X509Data><ds:X509Certificate>{X509_CERTIFICATE_INLINE}</ds:X509Certificate></ds:X509Data></ds:KeyInfo></ds:Signature><saml:Subject><saml:NameID Format="urn:oasis:names:tc:SAML:2.0:nameid-format:email" SPNameQualifier="example.net">randomuser@example.com</saml:NameID><saml:SubjectConfirmation Method="urn:oasis:names:tc:SAML:2.0:cm:bearer"><saml:SubjectConfirmationData InResponseTo="{REQUEST_ID}" NotOnOrAfter="2011-08-11T23:43:34Z" Recipient="{ACS_URL}"></saml:SubjectConfirmationData></saml:SubjectConfirmation></saml:Subject><saml:Conditions NotBefore="2011-08-11T23:38:04Z" NotOnOrAfter="2011-08-11T23:43:34Z"><saml:AudienceRestriction><saml:Audience>example.net</saml:Audience></saml:AudienceRestriction></saml:Conditions><saml:AuthnStatement AuthnInstant="2011-08-11T23:38:34Z"><saml:AuthnContext><saml:AuthnContextClassRef>urn:oasis:names:tc:SAML:2.0:ac:classes:Password</saml:AuthnContextClassRef></saml:AuthnContext></saml:AuthnStatement></saml:Assertion>'
    f'</samlp:Response>'
)

SIGNED_RESPONSE_WITH_SIGNED_ASSERTION_SALESFORCE_XML = (
    f'<samlp:Response xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol" Destination="{ACS_URL}" ID="{RESPONSE_ID}" InResponseTo="{REQUEST_ID}" IssueInstant="2011-08-11T23:38:34Z" Version="2.0">'
    f'<saml:Issuer xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion">{IDP_ISSUER}</saml:Issuer>'
    f'<ds:Signature xmlns:ds="http://www.w3.org/2000/09/xmldsig#"><ds:SignedInfo><ds:CanonicalizationMethod Algorithm="http://www.w3.org/2001/10/xml-exc-c14n#"></ds:CanonicalizationMethod><ds:SignatureMethod Algorithm="http://www.w3.org/2000/09/xmldsig#rsa-sha1"></ds:SignatureMethod><ds:Reference URI="#{RESPONSE_ID}"><ds:Transforms><ds:Transform Algorithm="http://www.w3.org/2000/09/xmldsig#enveloped-signature"></ds:Transform><ds:Transform Algorithm="http://www.w3.org/2001/10/xml-exc-c14n#"></ds:Transform></ds:Transforms><ds:DigestMethod Algorithm="http://www.w3.org/2000/09/xmldsig#sha1"></ds:DigestMethod><ds:DigestValue>sxi1OztMxi2taVoT3kxaVXQrVx4=</ds:DigestValue></ds:Reference></ds:SignedInfo><ds:SignatureValue>tErJwi7CBpFWXQRKxEcpkoNZKDv2D1D1hBOlEWWYOyrU5eGaaLFrQ/dMA3D7S0lGjGEf7YkkgiZOAE4dKVHhUg==</ds:SignatureValue><ds:KeyInfo><ds:X509Data><ds:X509Certificate>{X509_CERTIFICATE_INLINE}</ds:X509Certificate></ds:X509Data></ds:KeyInfo></ds:Signature>'
    f'<samlp:Status><samlp:StatusCode Value="urn:oasis:names:tc:SAML:2.0:status:Success"></samlp:StatusCode></samlp:Status>'
    f'<saml:Assertion xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion" ID="{ASSERTION_ID}" IssueInstant="2011-08-11T23:38:34Z" Version="2.0"><saml:Issuer>{IDP_ISSUER}</saml:Issuer><ds:Signature xmlns:ds="http://www.w3.org/2000/09/xmldsig#"><ds:SignedInfo><ds:CanonicalizationMethod Algorithm="http://www.w3.org/2001/10/xml-exc-c14n#"></ds:CanonicalizationMethod><ds:SignatureMethod Algorithm="http://www.w3.org/2000/09/xmldsig#rsa-sha1"></ds:SignatureMethod><ds:Reference URI="#{ASSERTION_ID}"><ds:Transforms><ds:Transform Algorithm="http://www.w3.org/2000/09/xmldsig#enveloped-signature"></ds:Transform><ds:Transform Algorithm="http://www.w3.org/2001/10/xml-exc-c14n#"></ds:Transform></ds:Transforms><ds:DigestMethod Algorithm="http://www.w3.org/2000/09/xmldsig#sha1"></ds:DigestMethod><ds:DigestValue>b7HwOJQgKYvhWcrUH17T8WXTY24=</ds:DigestValue></ds:Reference></ds:SignedInfo><ds:SignatureValue>WP+9aFiuj52WLW6ebwSaQhF2nU/wtyP3E2dudTa6mVTSjItpqduUqWR3rp/q39Hsehde6i+4RlbGQkZUwZSPEw==</ds:SignatureValue><ds:KeyInfo><ds:X509Data><ds:X509Certificate>{X509_CERTIFICATE_INLINE}</ds:X509Certificate></ds:X509Data></ds:KeyInfo></ds:Signature><saml:Subject><saml:NameID Format="urn:oasis:names:tc:SAML:2.0:nameid-format:email" SPNameQualifier="example.net">randomuser@example.com</saml:NameID><saml:SubjectConfirmation Method="urn:oasis:names:tc:SAML:2.0:cm:bearer"><saml:SubjectConfirmationData InResponseTo="{REQUEST_ID}" NotOnOrAfter="2011-08-11T23:43:34Z" Recipient="{ACS_URL}"></saml:SubjectConfirmationData></saml:SubjectConfirmation></saml:Subject><saml:Conditions NotBefore="2011-08-11T23:38:04Z" NotOnOrAfter="2011-08-11T23:43:34Z"><saml:AudienceRestriction><saml:Audience>example.net</saml:Audience></saml:AudienceRestriction></saml:Conditions><saml:AuthnStatement AuthnInstant="2011-08-11T23:38:34Z"><saml:AuthnContext><saml:AuthnContextClassRef>urn:oasis:names:tc:SAML:2.0:ac:classes:Password</saml:AuthnContextClassRef></saml:AuthnContext></saml:AuthnStatement></saml:Assertion>'
    f'</samlp:Response>'
)


class XmlTest(unittest.TestCase, XmlTestMixin):
    def _test(self, got: XmlNode, exp: str):
        got = c14n(got)
        self.assertXmlDocument(got)
        self.assertXmlEquivalentOutputs(got, exp)

    def _test_template(self, template_source, parameters, exp):
        template = template_source(parameters)
        self._test(template.xml, exp)


class TestSigning(XmlTest):
    def test1(self):
        digester = Sha1Digester()
        signer = RsaSha1Signer(PRIVATE_KEY)

        signature = SignatureTemplate.sign(
            "this is a test", CERTIFICATE, digester, signer, 'abcd' * 10)
        signature_xml = signature.xml
        expected_xml = SIGNATURE_TEMPLATE_STR
        self._test(signature_xml, expected_xml)


class TestAssertionSalesForce(XmlTest):
    def test_assertion(self):
        # This test simply verifies that the template isn't bad.
        params = {
            **IDP_PARAMS,
            **RESPONSE_PARAMS,
            **ASSERTION_SALESFORCE_PARAMS,
        }
        self._test_template(AssertionTemplate, params, ASSERTION_SALESFORCE.get_xml_string())

    def test_assertion_rendering(self):
        # Verifies that the xml rendering is OK.
        params = {
            **IDP_PARAMS,
            **RESPONSE_PARAMS,
            **ASSERTION_SALESFORCE_PARAMS,
        }
        got = AssertionTemplate(params)
        self._test(got.xml, ASSERTION_SALESFORCE.get_xml_string())

    def test_signed_assertion(self):
        # This test verifies that the assertion got signed properly.
        params = {
            **IDP_PARAMS,
            **RESPONSE_PARAMS,
            **ASSERTION_SALESFORCE_PARAMS,
        }

        digester = Sha1Digester()
        signer = RsaSha1Signer(PRIVATE_KEY)

        got = AssertionTemplate(params)
        got.sign(certificate=CERTIFICATE, signer=signer, digester=digester)
        self._test(got.xml, SIGNED_ASSERTION_SALESFORCE.get_xml_string())


class TestResponse(XmlTest):
    def test_response(self):
        # This test simply verifies that the template isn't bad.
        params = {
            **IDP_PARAMS,
            **RESPONSE_PARAMS,
        }

        template = ResponseTemplate(params, ASSERTION_SALESFORCE)
        template.get_xml_string()
        self._test(template.xml, RESPONSE_XML)

    def test_response_rendering(self):
        # Verifies that the rendering is OK.
        params = {
            **IDP_PARAMS,
            **RESPONSE_PARAMS,
        }
        got = ResponseTemplate(params, ASSERTION_SALESFORCE)
        self._test(got.xml, RESPONSE_XML)

    def test_response_with_signed_assertion(self):
        # This test also verifies that the template isn't bad.
        params = {
            **IDP_PARAMS,
            **RESPONSE_PARAMS,
        }
        got = ResponseTemplate(params, SIGNED_ASSERTION_SALESFORCE)
        self._test(got.xml, RESPONSE_WITH_SIGNED_ASSERTION_SALESFORCE_XML)

    def test_signed_response_with_signed_assertion(self):
        # This test verifies that the response got signed properly.
        params = {
            **IDP_PARAMS,
            **RESPONSE_PARAMS,
        }

        digester = Sha1Digester()
        signer = RsaSha1Signer(PRIVATE_KEY)

        got = ResponseTemplate(params, SIGNED_ASSERTION_SALESFORCE)
        got.sign(certificate=CERTIFICATE, signer=signer, digester=digester)
        self._test(got.xml, SIGNED_RESPONSE_WITH_SIGNED_ASSERTION_SALESFORCE_XML)


def test_loading_certificate():
    cert_from_file = certificate_from_file(CERTIFICATE_FILE)
    cert_from_string = certificate_from_string(X509_CERTIFICATE_DATA)
    assert cert_from_file.digest('sha1') == cert_from_string.digest('sha1')


def test_loading_private_key():
    pk_from_file = private_key_from_file(PRIVATE_KEY_FILE)
    pk_from_string = private_key_from_string(X509_PRIVATE_KEY_DATA)
    signer_from_file = RsaSha1Signer(pk_from_file)
    signer_from_string = RsaSha1Signer(pk_from_string)

    # It does not seem possible to compare PKey instances for equality, but the
    # same key should sign the same data to the same value, and different keys
    # will sign the same data to different values
    data = b'Hello, world!'
    assert signer_from_file(data) == signer_from_string(data)


def test_signing_data_with_private_key():
    private_key = private_key_from_string(X509_PRIVATE_KEY_DATA)
    signer = RsaSha1Signer(private_key)

    data = b'Some interesting data.'

    # Precalculated and verified to be correct. Check using openssl:
    #
    #   echo -n "Some interesting data." \
    #   | openssl dgst -sha1 -sign tests/keys/sample/sample-private-key.pem \
    #   | base64 --wrap=0
    expected = 'JYT2mxcW81Iht1HPoTbrQhX/kcOmssFwnuC+6WSbbRTalq1ZqRvrNmOiiny+FOsmrQi0VzVYT/jlJnho2dz4Xw=='
    assert signer(data) == expected
