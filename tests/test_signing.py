import unittest

import lxml.etree as ET
from xmlunittest import XmlTestMixin

from flask_saml2_idp import xml_render, xml_signing, xml_templates
from flask_saml2_idp.sp import salesforce
from flask_saml2_idp.utils import (
    certificate_from_file, certificate_from_string, private_key_from_file,
    private_key_from_string)
from flask_saml2_idp.xml_signing import get_signature_xml

from .base import CERTIFICATE, CERTIFICATE_FILE, PRIVATE_KEY, PRIVATE_KEY_FILE

IDP_PARAMS = {
    'ISSUER': 'http://127.0.0.1:8000',
}

REQUEST_PARAMS = {
    'ACS_URL': 'https://www.example.net/a/example.com/acs',
    'REQUEST_ID': 'mpjibjdppiodcpciaefmdahiipjpcghdcfjodkbi',
}

ASSERTION_SALESFORCE_PARAMS = {
    'ASSERTION_ID': '_7ccdda8bc6b328570c03b218d7521772998da45374',
    'ASSERTION_SIGNATURE': '',  # it's unsigned
    'AUDIENCE': 'example.net',
    'AUTH_INSTANT': '2011-08-11T23:38:34Z',
    'ISSUE_INSTANT': '2011-08-11T23:38:34Z',
    'NOT_BEFORE': '2011-08-11T23:38:04Z',
    'NOT_ON_OR_AFTER': '2011-08-11T23:43:34Z',
    'SESSION_NOT_ON_OR_AFTER': '2011-08-12T07:38:34Z',
    'SP_NAME_QUALIFIER': 'example.net',
    'SUBJECT': 'randomuser@example.com',
    'SUBJECT_FORMAT': 'urn:oasis:names:tc:SAML:2.0:nameid-format:email',
    '': 'b7HwOJQgKYvhWcrUH17T8WXTY24='
}

ASSERTION_SALESFORCE_STR = '<saml:Assertion xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion" ID="_7ccdda8bc6b328570c03b218d7521772998da45374" IssueInstant="2011-08-11T23:38:34Z" Version="2.0"><saml:Issuer>http://127.0.0.1:8000</saml:Issuer><saml:Subject><saml:NameID Format="urn:oasis:names:tc:SAML:2.0:nameid-format:email" SPNameQualifier="example.net">randomuser@example.com</saml:NameID><saml:SubjectConfirmation Method="urn:oasis:names:tc:SAML:2.0:cm:bearer"><saml:SubjectConfirmationData InResponseTo="mpjibjdppiodcpciaefmdahiipjpcghdcfjodkbi" NotOnOrAfter="2011-08-11T23:43:34Z" Recipient="https://www.example.net/a/example.com/acs"></saml:SubjectConfirmationData></saml:SubjectConfirmation></saml:Subject><saml:Conditions NotBefore="2011-08-11T23:38:04Z" NotOnOrAfter="2011-08-11T23:43:34Z"><saml:AudienceRestriction><saml:Audience>example.net</saml:Audience></saml:AudienceRestriction></saml:Conditions><saml:AuthnStatement AuthnInstant="2011-08-11T23:38:34Z"><saml:AuthnContext><saml:AuthnContextClassRef>urn:oasis:names:tc:SAML:2.0:ac:classes:Password</saml:AuthnContextClassRef></saml:AuthnContext></saml:AuthnStatement></saml:Assertion>'
ASSERTION_SALESFORCE_XML = ET.XML(ASSERTION_SALESFORCE_STR)
SIGNED_ASSERTION_SALESFORCE_STR = '<saml:Assertion xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion" ID="_7ccdda8bc6b328570c03b218d7521772998da45374" IssueInstant="2011-08-11T23:38:34Z" Version="2.0"><saml:Issuer>http://127.0.0.1:8000</saml:Issuer><ds:Signature xmlns:ds="http://www.w3.org/2000/09/xmldsig#"><ds:SignedInfo><ds:CanonicalizationMethod Algorithm="http://www.w3.org/2001/10/xml-exc-c14n#"></ds:CanonicalizationMethod><ds:SignatureMethod Algorithm="http://www.w3.org/2000/09/xmldsig#rsa-sha1"></ds:SignatureMethod><ds:Reference URI="#_7ccdda8bc6b328570c03b218d7521772998da45374"><ds:Transforms><ds:Transform Algorithm="http://www.w3.org/2000/09/xmldsig#enveloped-signature"></ds:Transform><ds:Transform Algorithm="http://www.w3.org/2001/10/xml-exc-c14n#"></ds:Transform></ds:Transforms><ds:DigestMethod Algorithm="http://www.w3.org/2000/09/xmldsig#sha1"></ds:DigestMethod><ds:DigestValue>b7HwOJQgKYvhWcrUH17T8WXTY24=</ds:DigestValue></ds:Reference></ds:SignedInfo><ds:SignatureValue>WP+9aFiuj52WLW6ebwSaQhF2nU/wtyP3E2dudTa6mVTSjItpqduUqWR3rp/q39Hsehde6i+4RlbGQkZUwZSPEw==</ds:SignatureValue><ds:KeyInfo><ds:X509Data><ds:X509Certificate>MIICKzCCAdWgAwIBAgIJAM8DxRNtPj90MA0GCSqGSIb3DQEBBQUAMEUxCzAJBgNVBAYTAkFVMRMwEQYDVQQIEwpTb21lLVN0YXRlMSEwHwYDVQQKExhJbnRlcm5ldCBXaWRnaXRzIFB0eSBMdGQwHhcNMTEwODEyMjA1MTIzWhcNMTIwODExMjA1MTIzWjBFMQswCQYDVQQGEwJBVTETMBEGA1UECBMKU29tZS1TdGF0ZTEhMB8GA1UEChMYSW50ZXJuZXQgV2lkZ2l0cyBQdHkgTHRkMFwwDQYJKoZIhvcNAQEBBQADSwAwSAJBANcNmgm4YlSUAr2xdWei5aRU/DbWtsQ47gjkv28Ekje3ob+6q0M+D5phwYDcv9ygYmuJ5wOi1cPprsWdFWmvSusCAwEAAaOBpzCBpDAdBgNVHQ4EFgQUzyBR9+vE8bygqvD6CZ/w6aQPikMwdQYDVR0jBG4wbIAUzyBR9+vE8bygqvD6CZ/w6aQPikOhSaRHMEUxCzAJBgNVBAYTAkFVMRMwEQYDVQQIEwpTb21lLVN0YXRlMSEwHwYDVQQKExhJbnRlcm5ldCBXaWRnaXRzIFB0eSBMdGSCCQDPA8UTbT4/dDAMBgNVHRMEBTADAQH/MA0GCSqGSIb3DQEBBQUAA0EAIQuPLA/mlMJAMF680kL7reX5WgyRwAtRzJK6FgNjE7kRaLZQ79UKYVYa0VAyrRdoNEyVhG4tJFEiQJzaLWsl/A==</ds:X509Certificate></ds:X509Data></ds:KeyInfo></ds:Signature><saml:Subject><saml:NameID Format="urn:oasis:names:tc:SAML:2.0:nameid-format:email" SPNameQualifier="example.net">randomuser@example.com</saml:NameID><saml:SubjectConfirmation Method="urn:oasis:names:tc:SAML:2.0:cm:bearer"><saml:SubjectConfirmationData InResponseTo="mpjibjdppiodcpciaefmdahiipjpcghdcfjodkbi" NotOnOrAfter="2011-08-11T23:43:34Z" Recipient="https://www.example.net/a/example.com/acs"></saml:SubjectConfirmationData></saml:SubjectConfirmation></saml:Subject><saml:Conditions NotBefore="2011-08-11T23:38:04Z" NotOnOrAfter="2011-08-11T23:43:34Z"><saml:AudienceRestriction><saml:Audience>example.net</saml:Audience></saml:AudienceRestriction></saml:Conditions><saml:AuthnStatement AuthnInstant="2011-08-11T23:38:34Z"><saml:AuthnContext><saml:AuthnContextClassRef>urn:oasis:names:tc:SAML:2.0:ac:classes:Password</saml:AuthnContextClassRef></saml:AuthnContext></saml:AuthnStatement></saml:Assertion>'
SIGNED_ASSERTION_SALESFORCE_XML = ET.XML(SIGNED_ASSERTION_SALESFORCE_STR)

RESPONSE_PARAMS = {
    'ASSERTION': '',
    'ISSUE_INSTANT': '2011-08-11T23:38:34Z',
    'NOT_ON_OR_AFTER': '2011-08-11T23:43:34Z',
    'RESPONSE_ID': '_2972e82c07bb5453956cc11fb19cad97ed26ff8bb4',
    'RESPONSE_SIGNATURE': '',
    'SP_NAME_QUALIFIER': 'example.net',
    'SUBJECT': 'randomuser@example.com',
    'SUBJECT_FORMAT': 'urn:oasis:names:tc:SAML:2.0:nameid-format:email',
}

RESPONSE_XML = '<samlp:Response xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol" Destination="https://www.example.net/a/example.com/acs" ID="_2972e82c07bb5453956cc11fb19cad97ed26ff8bb4" InResponseTo="mpjibjdppiodcpciaefmdahiipjpcghdcfjodkbi" IssueInstant="2011-08-11T23:38:34Z" Version="2.0"><saml:Issuer xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion">http://127.0.0.1:8000</saml:Issuer><samlp:Status><samlp:StatusCode Value="urn:oasis:names:tc:SAML:2.0:status:Success"></samlp:StatusCode></samlp:Status><saml:Assertion xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion" ID="_7ccdda8bc6b328570c03b218d7521772998da45374" IssueInstant="2011-08-11T23:38:34Z" Version="2.0"><saml:Issuer>http://127.0.0.1:8000</saml:Issuer><saml:Subject><saml:NameID Format="urn:oasis:names:tc:SAML:2.0:nameid-format:email" SPNameQualifier="example.net">randomuser@example.com</saml:NameID><saml:SubjectConfirmation Method="urn:oasis:names:tc:SAML:2.0:cm:bearer"><saml:SubjectConfirmationData InResponseTo="mpjibjdppiodcpciaefmdahiipjpcghdcfjodkbi" NotOnOrAfter="2011-08-11T23:43:34Z" Recipient="https://www.example.net/a/example.com/acs"></saml:SubjectConfirmationData></saml:SubjectConfirmation></saml:Subject><saml:Conditions NotBefore="2011-08-11T23:38:04Z" NotOnOrAfter="2011-08-11T23:43:34Z"><saml:AudienceRestriction><saml:Audience>example.net</saml:Audience></saml:AudienceRestriction></saml:Conditions><saml:AuthnStatement AuthnInstant="2011-08-11T23:38:34Z"><saml:AuthnContext><saml:AuthnContextClassRef>urn:oasis:names:tc:SAML:2.0:ac:classes:Password</saml:AuthnContextClassRef></saml:AuthnContext></saml:AuthnStatement></saml:Assertion></samlp:Response>'
RESPONSE_WITH_SIGNED_ASSERTION_SALESFORCE_XML = '<samlp:Response xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol" Destination="https://www.example.net/a/example.com/acs" ID="_2972e82c07bb5453956cc11fb19cad97ed26ff8bb4" InResponseTo="mpjibjdppiodcpciaefmdahiipjpcghdcfjodkbi" IssueInstant="2011-08-11T23:38:34Z" Version="2.0"><saml:Issuer xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion">http://127.0.0.1:8000</saml:Issuer><samlp:Status><samlp:StatusCode Value="urn:oasis:names:tc:SAML:2.0:status:Success"></samlp:StatusCode></samlp:Status><saml:Assertion xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion" ID="_7ccdda8bc6b328570c03b218d7521772998da45374" IssueInstant="2011-08-11T23:38:34Z" Version="2.0"><saml:Issuer>http://127.0.0.1:8000</saml:Issuer><ds:Signature xmlns:ds="http://www.w3.org/2000/09/xmldsig#"><ds:SignedInfo><ds:CanonicalizationMethod Algorithm="http://www.w3.org/2001/10/xml-exc-c14n#"></ds:CanonicalizationMethod><ds:SignatureMethod Algorithm="http://www.w3.org/2000/09/xmldsig#rsa-sha1"></ds:SignatureMethod><ds:Reference URI="#_7ccdda8bc6b328570c03b218d7521772998da45374"><ds:Transforms><ds:Transform Algorithm="http://www.w3.org/2000/09/xmldsig#enveloped-signature"></ds:Transform><ds:Transform Algorithm="http://www.w3.org/2001/10/xml-exc-c14n#"></ds:Transform></ds:Transforms><ds:DigestMethod Algorithm="http://www.w3.org/2000/09/xmldsig#sha1"></ds:DigestMethod><ds:DigestValue>b7HwOJQgKYvhWcrUH17T8WXTY24=</ds:DigestValue></ds:Reference></ds:SignedInfo><ds:SignatureValue>WP+9aFiuj52WLW6ebwSaQhF2nU/wtyP3E2dudTa6mVTSjItpqduUqWR3rp/q39Hsehde6i+4RlbGQkZUwZSPEw==</ds:SignatureValue><ds:KeyInfo><ds:X509Data><ds:X509Certificate>MIICKzCCAdWgAwIBAgIJAM8DxRNtPj90MA0GCSqGSIb3DQEBBQUAMEUxCzAJBgNVBAYTAkFVMRMwEQYDVQQIEwpTb21lLVN0YXRlMSEwHwYDVQQKExhJbnRlcm5ldCBXaWRnaXRzIFB0eSBMdGQwHhcNMTEwODEyMjA1MTIzWhcNMTIwODExMjA1MTIzWjBFMQswCQYDVQQGEwJBVTETMBEGA1UECBMKU29tZS1TdGF0ZTEhMB8GA1UEChMYSW50ZXJuZXQgV2lkZ2l0cyBQdHkgTHRkMFwwDQYJKoZIhvcNAQEBBQADSwAwSAJBANcNmgm4YlSUAr2xdWei5aRU/DbWtsQ47gjkv28Ekje3ob+6q0M+D5phwYDcv9ygYmuJ5wOi1cPprsWdFWmvSusCAwEAAaOBpzCBpDAdBgNVHQ4EFgQUzyBR9+vE8bygqvD6CZ/w6aQPikMwdQYDVR0jBG4wbIAUzyBR9+vE8bygqvD6CZ/w6aQPikOhSaRHMEUxCzAJBgNVBAYTAkFVMRMwEQYDVQQIEwpTb21lLVN0YXRlMSEwHwYDVQQKExhJbnRlcm5ldCBXaWRnaXRzIFB0eSBMdGSCCQDPA8UTbT4/dDAMBgNVHRMEBTADAQH/MA0GCSqGSIb3DQEBBQUAA0EAIQuPLA/mlMJAMF680kL7reX5WgyRwAtRzJK6FgNjE7kRaLZQ79UKYVYa0VAyrRdoNEyVhG4tJFEiQJzaLWsl/A==</ds:X509Certificate></ds:X509Data></ds:KeyInfo></ds:Signature><saml:Subject><saml:NameID Format="urn:oasis:names:tc:SAML:2.0:nameid-format:email" SPNameQualifier="example.net">randomuser@example.com</saml:NameID><saml:SubjectConfirmation Method="urn:oasis:names:tc:SAML:2.0:cm:bearer"><saml:SubjectConfirmationData InResponseTo="mpjibjdppiodcpciaefmdahiipjpcghdcfjodkbi" NotOnOrAfter="2011-08-11T23:43:34Z" Recipient="https://www.example.net/a/example.com/acs"></saml:SubjectConfirmationData></saml:SubjectConfirmation></saml:Subject><saml:Conditions NotBefore="2011-08-11T23:38:04Z" NotOnOrAfter="2011-08-11T23:43:34Z"><saml:AudienceRestriction><saml:Audience>example.net</saml:Audience></saml:AudienceRestriction></saml:Conditions><saml:AuthnStatement AuthnInstant="2011-08-11T23:38:34Z"><saml:AuthnContext><saml:AuthnContextClassRef>urn:oasis:names:tc:SAML:2.0:ac:classes:Password</saml:AuthnContextClassRef></saml:AuthnContext></saml:AuthnStatement></saml:Assertion></samlp:Response>'

SIGNED_RESPONSE_WITH_SIGNED_ASSERTION_SALESFORCE_XML = '<samlp:Response xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol" Destination="https://www.example.net/a/example.com/acs" ID="_2972e82c07bb5453956cc11fb19cad97ed26ff8bb4" InResponseTo="mpjibjdppiodcpciaefmdahiipjpcghdcfjodkbi" IssueInstant="2011-08-11T23:38:34Z" Version="2.0"><saml:Issuer xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion">http://127.0.0.1:8000</saml:Issuer><ds:Signature xmlns:ds="http://www.w3.org/2000/09/xmldsig#"><ds:SignedInfo><ds:CanonicalizationMethod Algorithm="http://www.w3.org/2001/10/xml-exc-c14n#"></ds:CanonicalizationMethod><ds:SignatureMethod Algorithm="http://www.w3.org/2000/09/xmldsig#rsa-sha1"></ds:SignatureMethod><ds:Reference URI="#_2972e82c07bb5453956cc11fb19cad97ed26ff8bb4"><ds:Transforms><ds:Transform Algorithm="http://www.w3.org/2000/09/xmldsig#enveloped-signature"></ds:Transform><ds:Transform Algorithm="http://www.w3.org/2001/10/xml-exc-c14n#"></ds:Transform></ds:Transforms><ds:DigestMethod Algorithm="http://www.w3.org/2000/09/xmldsig#sha1"></ds:DigestMethod><ds:DigestValue>sxi1OztMxi2taVoT3kxaVXQrVx4=</ds:DigestValue></ds:Reference></ds:SignedInfo><ds:SignatureValue>tErJwi7CBpFWXQRKxEcpkoNZKDv2D1D1hBOlEWWYOyrU5eGaaLFrQ/dMA3D7S0lGjGEf7YkkgiZOAE4dKVHhUg==</ds:SignatureValue><ds:KeyInfo><ds:X509Data><ds:X509Certificate>MIICKzCCAdWgAwIBAgIJAM8DxRNtPj90MA0GCSqGSIb3DQEBBQUAMEUxCzAJBgNVBAYTAkFVMRMwEQYDVQQIEwpTb21lLVN0YXRlMSEwHwYDVQQKExhJbnRlcm5ldCBXaWRnaXRzIFB0eSBMdGQwHhcNMTEwODEyMjA1MTIzWhcNMTIwODExMjA1MTIzWjBFMQswCQYDVQQGEwJBVTETMBEGA1UECBMKU29tZS1TdGF0ZTEhMB8GA1UEChMYSW50ZXJuZXQgV2lkZ2l0cyBQdHkgTHRkMFwwDQYJKoZIhvcNAQEBBQADSwAwSAJBANcNmgm4YlSUAr2xdWei5aRU/DbWtsQ47gjkv28Ekje3ob+6q0M+D5phwYDcv9ygYmuJ5wOi1cPprsWdFWmvSusCAwEAAaOBpzCBpDAdBgNVHQ4EFgQUzyBR9+vE8bygqvD6CZ/w6aQPikMwdQYDVR0jBG4wbIAUzyBR9+vE8bygqvD6CZ/w6aQPikOhSaRHMEUxCzAJBgNVBAYTAkFVMRMwEQYDVQQIEwpTb21lLVN0YXRlMSEwHwYDVQQKExhJbnRlcm5ldCBXaWRnaXRzIFB0eSBMdGSCCQDPA8UTbT4/dDAMBgNVHRMEBTADAQH/MA0GCSqGSIb3DQEBBQUAA0EAIQuPLA/mlMJAMF680kL7reX5WgyRwAtRzJK6FgNjE7kRaLZQ79UKYVYa0VAyrRdoNEyVhG4tJFEiQJzaLWsl/A==</ds:X509Certificate></ds:X509Data></ds:KeyInfo></ds:Signature><samlp:Status><samlp:StatusCode Value="urn:oasis:names:tc:SAML:2.0:status:Success"></samlp:StatusCode></samlp:Status><saml:Assertion xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion" ID="_7ccdda8bc6b328570c03b218d7521772998da45374" IssueInstant="2011-08-11T23:38:34Z" Version="2.0"><saml:Issuer>http://127.0.0.1:8000</saml:Issuer><ds:Signature xmlns:ds="http://www.w3.org/2000/09/xmldsig#"><ds:SignedInfo><ds:CanonicalizationMethod Algorithm="http://www.w3.org/2001/10/xml-exc-c14n#"></ds:CanonicalizationMethod><ds:SignatureMethod Algorithm="http://www.w3.org/2000/09/xmldsig#rsa-sha1"></ds:SignatureMethod><ds:Reference URI="#_7ccdda8bc6b328570c03b218d7521772998da45374"><ds:Transforms><ds:Transform Algorithm="http://www.w3.org/2000/09/xmldsig#enveloped-signature"></ds:Transform><ds:Transform Algorithm="http://www.w3.org/2001/10/xml-exc-c14n#"></ds:Transform></ds:Transforms><ds:DigestMethod Algorithm="http://www.w3.org/2000/09/xmldsig#sha1"></ds:DigestMethod><ds:DigestValue>b7HwOJQgKYvhWcrUH17T8WXTY24=</ds:DigestValue></ds:Reference></ds:SignedInfo><ds:SignatureValue>WP+9aFiuj52WLW6ebwSaQhF2nU/wtyP3E2dudTa6mVTSjItpqduUqWR3rp/q39Hsehde6i+4RlbGQkZUwZSPEw==</ds:SignatureValue><ds:KeyInfo><ds:X509Data><ds:X509Certificate>MIICKzCCAdWgAwIBAgIJAM8DxRNtPj90MA0GCSqGSIb3DQEBBQUAMEUxCzAJBgNVBAYTAkFVMRMwEQYDVQQIEwpTb21lLVN0YXRlMSEwHwYDVQQKExhJbnRlcm5ldCBXaWRnaXRzIFB0eSBMdGQwHhcNMTEwODEyMjA1MTIzWhcNMTIwODExMjA1MTIzWjBFMQswCQYDVQQGEwJBVTETMBEGA1UECBMKU29tZS1TdGF0ZTEhMB8GA1UEChMYSW50ZXJuZXQgV2lkZ2l0cyBQdHkgTHRkMFwwDQYJKoZIhvcNAQEBBQADSwAwSAJBANcNmgm4YlSUAr2xdWei5aRU/DbWtsQ47gjkv28Ekje3ob+6q0M+D5phwYDcv9ygYmuJ5wOi1cPprsWdFWmvSusCAwEAAaOBpzCBpDAdBgNVHQ4EFgQUzyBR9+vE8bygqvD6CZ/w6aQPikMwdQYDVR0jBG4wbIAUzyBR9+vE8bygqvD6CZ/w6aQPikOhSaRHMEUxCzAJBgNVBAYTAkFVMRMwEQYDVQQIEwpTb21lLVN0YXRlMSEwHwYDVQQKExhJbnRlcm5ldCBXaWRnaXRzIFB0eSBMdGSCCQDPA8UTbT4/dDAMBgNVHRMEBTADAQH/MA0GCSqGSIb3DQEBBQUAA0EAIQuPLA/mlMJAMF680kL7reX5WgyRwAtRzJK6FgNjE7kRaLZQ79UKYVYa0VAyrRdoNEyVhG4tJFEiQJzaLWsl/A==</ds:X509Certificate></ds:X509Data></ds:KeyInfo></ds:Signature><saml:Subject><saml:NameID Format="urn:oasis:names:tc:SAML:2.0:nameid-format:email" SPNameQualifier="example.net">randomuser@example.com</saml:NameID><saml:SubjectConfirmation Method="urn:oasis:names:tc:SAML:2.0:cm:bearer"><saml:SubjectConfirmationData InResponseTo="mpjibjdppiodcpciaefmdahiipjpcghdcfjodkbi" NotOnOrAfter="2011-08-11T23:43:34Z" Recipient="https://www.example.net/a/example.com/acs"></saml:SubjectConfirmationData></saml:SubjectConfirmation></saml:Subject><saml:Conditions NotBefore="2011-08-11T23:38:04Z" NotOnOrAfter="2011-08-11T23:43:34Z"><saml:AudienceRestriction><saml:Audience>example.net</saml:Audience></saml:AudienceRestriction></saml:Conditions><saml:AuthnStatement AuthnInstant="2011-08-11T23:38:34Z"><saml:AuthnContext><saml:AuthnContextClassRef>urn:oasis:names:tc:SAML:2.0:ac:classes:Password</saml:AuthnContextClassRef></saml:AuthnContext></saml:AuthnStatement></saml:Assertion></samlp:Response>'

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


class XmlTest(unittest.TestCase, XmlTestMixin):
    def _test(self, got, exp):
        if type(got) != str:
            got = ET.tostring(got, method='c14n', exclusive=True).decode('utf-8')
        if type(exp) != str:
            exp = ET.tostring(exp, method='c14n', exclusive=True).decode('utf-8')
        self.assertXmlDocument(got)
        self.assertXmlEquivalentOutputs(got, exp)

    def _test_template(self, template_source, parameters, exp):
        xml_render._get_in_response_to(parameters)
        got = template_source(parameters).get_xml_string()
        self._test(got, exp)


class TestSigning(XmlTest):
    def test1(self):
        signature_xml = get_signature_xml(
            CERTIFICATE, PRIVATE_KEY, "this is a test", 'abcd' * 10)
        expected_xml = '<ds:Signature xmlns:ds="http://www.w3.org/2000/09/xmldsig#"><ds:SignedInfo><ds:CanonicalizationMethod Algorithm="http://www.w3.org/2001/10/xml-exc-c14n#"></ds:CanonicalizationMethod><ds:SignatureMethod Algorithm="http://www.w3.org/2000/09/xmldsig#rsa-sha1"></ds:SignatureMethod><ds:Reference URI="#abcdabcdabcdabcdabcdabcdabcdabcdabcdabcd"><ds:Transforms><ds:Transform Algorithm="http://www.w3.org/2000/09/xmldsig#enveloped-signature"></ds:Transform><ds:Transform Algorithm="http://www.w3.org/2001/10/xml-exc-c14n#"></ds:Transform></ds:Transforms><ds:DigestMethod Algorithm="http://www.w3.org/2000/09/xmldsig#sha1"></ds:DigestMethod><ds:DigestValue>+ia+Gd5r/5P3C8IwhDTkpEC7rQI=</ds:DigestValue></ds:Reference></ds:SignedInfo><ds:SignatureValue>t1IywxEzobY8ZyHL+iuB+E3zzVAWByUjRqFTdyNerGbGSRwo0oYWx6hcYX+ST1DTDaQ50gV2PJeibbykFsA3vQ==</ds:SignatureValue><ds:KeyInfo><ds:X509Data><ds:X509Certificate>MIICKzCCAdWgAwIBAgIJAM8DxRNtPj90MA0GCSqGSIb3DQEBBQUAMEUxCzAJBgNVBAYTAkFVMRMwEQYDVQQIEwpTb21lLVN0YXRlMSEwHwYDVQQKExhJbnRlcm5ldCBXaWRnaXRzIFB0eSBMdGQwHhcNMTEwODEyMjA1MTIzWhcNMTIwODExMjA1MTIzWjBFMQswCQYDVQQGEwJBVTETMBEGA1UECBMKU29tZS1TdGF0ZTEhMB8GA1UEChMYSW50ZXJuZXQgV2lkZ2l0cyBQdHkgTHRkMFwwDQYJKoZIhvcNAQEBBQADSwAwSAJBANcNmgm4YlSUAr2xdWei5aRU/DbWtsQ47gjkv28Ekje3ob+6q0M+D5phwYDcv9ygYmuJ5wOi1cPprsWdFWmvSusCAwEAAaOBpzCBpDAdBgNVHQ4EFgQUzyBR9+vE8bygqvD6CZ/w6aQPikMwdQYDVR0jBG4wbIAUzyBR9+vE8bygqvD6CZ/w6aQPikOhSaRHMEUxCzAJBgNVBAYTAkFVMRMwEQYDVQQIEwpTb21lLVN0YXRlMSEwHwYDVQQKExhJbnRlcm5ldCBXaWRnaXRzIFB0eSBMdGSCCQDPA8UTbT4/dDAMBgNVHRMEBTADAQH/MA0GCSqGSIb3DQEBBQUAA0EAIQuPLA/mlMJAMF680kL7reX5WgyRwAtRzJK6FgNjE7kRaLZQ79UKYVYa0VAyrRdoNEyVhG4tJFEiQJzaLWsl/A==</ds:X509Certificate></ds:X509Data></ds:KeyInfo></ds:Signature>'
        self._test(ET.tostring(signature_xml, method='c14n').decode('utf-8'), expected_xml)


class TestAssertionSalesForce(XmlTest):
    def test_assertion(self):
        # This test simply verifies that the template isn't bad.
        params = {
            **IDP_PARAMS,
            **REQUEST_PARAMS,
            **RESPONSE_PARAMS,
            **ASSERTION_SALESFORCE_PARAMS,
        }
        self._test_template(salesforce.SalesforceAssertionTemplate, params, ASSERTION_SALESFORCE_XML)

    def test_assertion_rendering(self):
        # Verifies that the xml rendering is OK.
        params = {
            **IDP_PARAMS,
            **REQUEST_PARAMS,
            **RESPONSE_PARAMS,
            **ASSERTION_SALESFORCE_PARAMS,
        }
        got = salesforce.get_assertion_xml(parameters=params, signed=False)
        self._test(got, ASSERTION_SALESFORCE_XML)

    def test_signed_assertion(self):
        # This test verifies that the assertion got signed properly.
        params = {
            **IDP_PARAMS,
            **REQUEST_PARAMS,
            **RESPONSE_PARAMS,
            **ASSERTION_SALESFORCE_PARAMS,
        }
        got = salesforce.get_assertion_xml(parameters=params, signed=True, certificate=CERTIFICATE, private_key=PRIVATE_KEY)
        self._test(got, SIGNED_ASSERTION_SALESFORCE_XML)


class TestResponse(XmlTest):
    def test_response(self):
        # This test simply verifies that the template isn't bad.
        params = {
            **IDP_PARAMS,
            **REQUEST_PARAMS,
            **RESPONSE_PARAMS,
        }
        xml_render._get_in_response_to(params)

        template = xml_templates.ResponseTemplate(params, ASSERTION_SALESFORCE_XML)
        template.generate_xml()
        got = template.get_xml_string()

        self._test(got, RESPONSE_XML)

    def test_response_rendering(self):
        # Verifies that the rendering is OK.
        params = {
            **IDP_PARAMS,
            **REQUEST_PARAMS,
            **RESPONSE_PARAMS,
        }
        got = xml_render.get_response_xml(
            params, ASSERTION_SALESFORCE_XML, signed=False)
        self._test(got, RESPONSE_XML)

    def test_response_with_signed_assertion(self):
        # This test also verifies that the template isn't bad.
        params = {
            **IDP_PARAMS,
            **REQUEST_PARAMS,
            **RESPONSE_PARAMS,
        }
        got = xml_render.get_response_xml(
            params, SIGNED_ASSERTION_SALESFORCE_XML, signed=False)
        self._test(got, RESPONSE_WITH_SIGNED_ASSERTION_SALESFORCE_XML)

    def test_signed_response_with_signed_assertion(self):
        # This test verifies that the response got signed properly.
        params = {
            **IDP_PARAMS,
            **REQUEST_PARAMS,
            **RESPONSE_PARAMS,
        }
        got = xml_render.get_response_xml(
            params, SIGNED_ASSERTION_SALESFORCE_XML,
            signed=True, certificate=CERTIFICATE, private_key=PRIVATE_KEY)
        self._test(got, SIGNED_RESPONSE_WITH_SIGNED_ASSERTION_SALESFORCE_XML)


def test_loading_certificate():
    cert_from_file = certificate_from_file(CERTIFICATE_FILE)
    cert_from_string = certificate_from_string(X509_CERTIFICATE_DATA)
    assert cert_from_file.digest('sha1') == cert_from_string.digest('sha1')


def test_loading_private_key():
    pk_from_file = private_key_from_file(PRIVATE_KEY_FILE)
    pk_from_string = private_key_from_string(X509_PRIVATE_KEY_DATA)

    # It does not seem possible to compare PKey instances for equality, but the
    # same key should sign the same data to the same value, and different keys
    # will sign the same data to different values
    data = 'Hello, world!'
    signed_from_file = xml_signing.sign_with_rsa(pk_from_file, data)
    signed_from_string = xml_signing.sign_with_rsa(pk_from_string, data)
    assert signed_from_file == signed_from_string


def test_signing_data_with_private_key():
    private_key = private_key_from_string(X509_PRIVATE_KEY_DATA)

    data = "Some interesting data."

    # Precalculated and verified to be correct. Check using openssl:
    #
    #   echo -n "Some interesting data." \
    #   | openssl dgst -sha1 -sign tests/keys/sample/sample-private-key.pem \
    #   | base64 --wrap=0
    expected = 'JYT2mxcW81Iht1HPoTbrQhX/kcOmssFwnuC+6WSbbRTalq1ZqRvrNmOiiny+FOsmrQi0VzVYT/jlJnho2dz4Xw=='
    signature = xml_signing.sign_with_rsa(private_key, data)
    assert signature == expected
