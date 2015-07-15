import string
import unittest
from saml2idp import xml_render
from saml2idp.xml_signing import get_signature_xml
from saml2idp.xml_templates import ASSERTION_SALESFORCE, RESPONSE

IDP_PARAMS = {
    'ISSUER': 'http://127.0.0.1:8000',
}

REQUEST_PARAMS = {
    'ACS_URL': 'https://www.example.net/a/example.com/acs',
    'REQUEST_ID': 'mpjibjdppiodcpciaefmdahiipjpcghdcfjodkbi',
}

ASSERTION_SALESFORCE_PARAMS = {
    'ASSERTION_ID': '_7ccdda8bc6b328570c03b218d7521772998da45374',
    'ASSERTION_SIGNATURE': '', # it's unsigned
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

ASSERTION_SALESFORCE_XML = '<saml:Assertion xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion" ID="_7ccdda8bc6b328570c03b218d7521772998da45374" IssueInstant="2011-08-11T23:38:34Z" Version="2.0"><saml:Issuer>http://127.0.0.1:8000</saml:Issuer><saml:Subject><saml:NameID Format="urn:oasis:names:tc:SAML:2.0:nameid-format:email" SPNameQualifier="example.net">randomuser@example.com</saml:NameID><saml:SubjectConfirmation Method="urn:oasis:names:tc:SAML:2.0:cm:bearer"><saml:SubjectConfirmationData InResponseTo="mpjibjdppiodcpciaefmdahiipjpcghdcfjodkbi" NotOnOrAfter="2011-08-11T23:43:34Z" Recipient="https://www.example.net/a/example.com/acs"></saml:SubjectConfirmationData></saml:SubjectConfirmation></saml:Subject><saml:Conditions NotBefore="2011-08-11T23:38:04Z" NotOnOrAfter="2011-08-11T23:43:34Z"><saml:AudienceRestriction><saml:Audience>example.net</saml:Audience></saml:AudienceRestriction></saml:Conditions><saml:AuthnStatement AuthnInstant="2011-08-11T23:38:34Z"><saml:AuthnContext><saml:AuthnContextClassRef>urn:oasis:names:tc:SAML:2.0:ac:classes:Password</saml:AuthnContextClassRef></saml:AuthnContext></saml:AuthnStatement></saml:Assertion>'
SIGNED_ASSERTION_SALESFORCE_XML = '<saml:Assertion xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion" ID="_7ccdda8bc6b328570c03b218d7521772998da45374" IssueInstant="2011-08-11T23:38:34Z" Version="2.0"><saml:Issuer>http://127.0.0.1:8000</saml:Issuer><ds:Signature xmlns:ds="http://www.w3.org/2000/09/xmldsig#"><ds:SignedInfo><ds:CanonicalizationMethod Algorithm="http://www.w3.org/2001/10/xml-exc-c14n#"></ds:CanonicalizationMethod><ds:SignatureMethod Algorithm="http://www.w3.org/2000/09/xmldsig#rsa-sha1"></ds:SignatureMethod><ds:Reference URI="#_7ccdda8bc6b328570c03b218d7521772998da45374"><ds:Transforms><ds:Transform Algorithm="http://www.w3.org/2000/09/xmldsig#enveloped-signature"></ds:Transform><ds:Transform Algorithm="http://www.w3.org/2001/10/xml-exc-c14n#"></ds:Transform></ds:Transforms><ds:DigestMethod Algorithm="http://www.w3.org/2000/09/xmldsig#sha1"></ds:DigestMethod><ds:DigestValue>b7HwOJQgKYvhWcrUH17T8WXTY24=</ds:DigestValue></ds:Reference></ds:SignedInfo><ds:SignatureValue>WP+9aFiuj52WLW6ebwSaQhF2nU/wtyP3E2dudTa6mVTSjItpqduUqWR3rp/q39Hsehde6i+4RlbGQkZUwZSPEw==</ds:SignatureValue><ds:KeyInfo><ds:X509Data><ds:X509Certificate>MIICKzCCAdWgAwIBAgIJAM8DxRNtPj90MA0GCSqGSIb3DQEBBQUAMEUxCzAJBgNVBAYTAkFVMRMwEQYDVQQIEwpTb21lLVN0YXRlMSEwHwYDVQQKExhJbnRlcm5ldCBXaWRnaXRzIFB0eSBMdGQwHhcNMTEwODEyMjA1MTIzWhcNMTIwODExMjA1MTIzWjBFMQswCQYDVQQGEwJBVTETMBEGA1UECBMKU29tZS1TdGF0ZTEhMB8GA1UEChMYSW50ZXJuZXQgV2lkZ2l0cyBQdHkgTHRkMFwwDQYJKoZIhvcNAQEBBQADSwAwSAJBANcNmgm4YlSUAr2xdWei5aRU/DbWtsQ47gjkv28Ekje3ob+6q0M+D5phwYDcv9ygYmuJ5wOi1cPprsWdFWmvSusCAwEAAaOBpzCBpDAdBgNVHQ4EFgQUzyBR9+vE8bygqvD6CZ/w6aQPikMwdQYDVR0jBG4wbIAUzyBR9+vE8bygqvD6CZ/w6aQPikOhSaRHMEUxCzAJBgNVBAYTAkFVMRMwEQYDVQQIEwpTb21lLVN0YXRlMSEwHwYDVQQKExhJbnRlcm5ldCBXaWRnaXRzIFB0eSBMdGSCCQDPA8UTbT4/dDAMBgNVHRMEBTADAQH/MA0GCSqGSIb3DQEBBQUAA0EAIQuPLA/mlMJAMF680kL7reX5WgyRwAtRzJK6FgNjE7kRaLZQ79UKYVYa0VAyrRdoNEyVhG4tJFEiQJzaLWsl/A==</ds:X509Certificate></ds:X509Data></ds:KeyInfo></ds:Signature><saml:Subject><saml:NameID Format="urn:oasis:names:tc:SAML:2.0:nameid-format:email" SPNameQualifier="example.net">randomuser@example.com</saml:NameID><saml:SubjectConfirmation Method="urn:oasis:names:tc:SAML:2.0:cm:bearer"><saml:SubjectConfirmationData InResponseTo="mpjibjdppiodcpciaefmdahiipjpcghdcfjodkbi" NotOnOrAfter="2011-08-11T23:43:34Z" Recipient="https://www.example.net/a/example.com/acs"></saml:SubjectConfirmationData></saml:SubjectConfirmation></saml:Subject><saml:Conditions NotBefore="2011-08-11T23:38:04Z" NotOnOrAfter="2011-08-11T23:43:34Z"><saml:AudienceRestriction><saml:Audience>example.net</saml:Audience></saml:AudienceRestriction></saml:Conditions><saml:AuthnStatement AuthnInstant="2011-08-11T23:38:34Z"><saml:AuthnContext><saml:AuthnContextClassRef>urn:oasis:names:tc:SAML:2.0:ac:classes:Password</saml:AuthnContextClassRef></saml:AuthnContext></saml:AuthnStatement></saml:Assertion>'

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

class XmlTest(unittest.TestCase):
    def _test(self, got, exp):
        #TODO: Maybe provide more meaningful output. YAGNI?
        msg = 'Did not get expected XML.\nExp: %s\nGot: %s' % (exp, got)
        self.assertEqual(exp, got, msg)

    def _test_template(self, template_source, parameters, exp):
        xml_render._get_in_response_to(parameters)
        xml_render._get_subject(parameters)
        xml_render._get_attribute_statement(parameters)
        got = string.Template(template_source).substitute(parameters)
        self._test(got, exp)

class TestSigning(XmlTest):
    def test1(self):
        signature_xml = get_signature_xml("this is a test", 'abcd' * 10)
        expected_xml = '<ds:Signature xmlns:ds="http://www.w3.org/2000/09/xmldsig#"><ds:SignedInfo><ds:CanonicalizationMethod Algorithm="http://www.w3.org/2001/10/xml-exc-c14n#"></ds:CanonicalizationMethod><ds:SignatureMethod Algorithm="http://www.w3.org/2000/09/xmldsig#rsa-sha1"></ds:SignatureMethod><ds:Reference URI="#abcdabcdabcdabcdabcdabcdabcdabcdabcdabcd"><ds:Transforms><ds:Transform Algorithm="http://www.w3.org/2000/09/xmldsig#enveloped-signature"></ds:Transform><ds:Transform Algorithm="http://www.w3.org/2001/10/xml-exc-c14n#"></ds:Transform></ds:Transforms><ds:DigestMethod Algorithm="http://www.w3.org/2000/09/xmldsig#sha1"></ds:DigestMethod><ds:DigestValue>+ia+Gd5r/5P3C8IwhDTkpEC7rQI=</ds:DigestValue></ds:Reference></ds:SignedInfo><ds:SignatureValue>t1IywxEzobY8ZyHL+iuB+E3zzVAWByUjRqFTdyNerGbGSRwo0oYWx6hcYX+ST1DTDaQ50gV2PJeibbykFsA3vQ==</ds:SignatureValue><ds:KeyInfo><ds:X509Data><ds:X509Certificate>MIICKzCCAdWgAwIBAgIJAM8DxRNtPj90MA0GCSqGSIb3DQEBBQUAMEUxCzAJBgNVBAYTAkFVMRMwEQYDVQQIEwpTb21lLVN0YXRlMSEwHwYDVQQKExhJbnRlcm5ldCBXaWRnaXRzIFB0eSBMdGQwHhcNMTEwODEyMjA1MTIzWhcNMTIwODExMjA1MTIzWjBFMQswCQYDVQQGEwJBVTETMBEGA1UECBMKU29tZS1TdGF0ZTEhMB8GA1UEChMYSW50ZXJuZXQgV2lkZ2l0cyBQdHkgTHRkMFwwDQYJKoZIhvcNAQEBBQADSwAwSAJBANcNmgm4YlSUAr2xdWei5aRU/DbWtsQ47gjkv28Ekje3ob+6q0M+D5phwYDcv9ygYmuJ5wOi1cPprsWdFWmvSusCAwEAAaOBpzCBpDAdBgNVHQ4EFgQUzyBR9+vE8bygqvD6CZ/w6aQPikMwdQYDVR0jBG4wbIAUzyBR9+vE8bygqvD6CZ/w6aQPikOhSaRHMEUxCzAJBgNVBAYTAkFVMRMwEQYDVQQIEwpTb21lLVN0YXRlMSEwHwYDVQQKExhJbnRlcm5ldCBXaWRnaXRzIFB0eSBMdGSCCQDPA8UTbT4/dDAMBgNVHRMEBTADAQH/MA0GCSqGSIb3DQEBBQUAA0EAIQuPLA/mlMJAMF680kL7reX5WgyRwAtRzJK6FgNjE7kRaLZQ79UKYVYa0VAyrRdoNEyVhG4tJFEiQJzaLWsl/A==</ds:X509Certificate></ds:X509Data></ds:KeyInfo></ds:Signature>'
        self._test(signature_xml, expected_xml)

class TestAssertionSalesForce(XmlTest):
    def test_assertion(self):
        # This test simply verifies that the template isn't bad.
        params = {}
        params.update(IDP_PARAMS)
        params.update(REQUEST_PARAMS)
        params.update(ASSERTION_SALESFORCE_PARAMS)
        self._test_template(ASSERTION_SALESFORCE, params, ASSERTION_SALESFORCE_XML)

    def test_assertion_rendering(self):
        # Verifies that the xml rendering is OK.
        params = {}
        params.update(IDP_PARAMS)
        params.update(REQUEST_PARAMS)
        params.update(ASSERTION_SALESFORCE_PARAMS)
        got = xml_render.get_assertion_salesforce_xml(params, signed=False)
        self._test(got, ASSERTION_SALESFORCE_XML)

    def test_signed_assertion(self):
        # This test verifies that the assertion got signed properly.
        params = {}
        params.update(IDP_PARAMS)
        params.update(REQUEST_PARAMS)
        params.update(ASSERTION_SALESFORCE_PARAMS)
        got = xml_render.get_assertion_salesforce_xml(params, signed=True)
        self._test(got, SIGNED_ASSERTION_SALESFORCE_XML)


class TestResponse(XmlTest):
    def test_response(self):
        # This test simply verifies that the template isn't bad.
        params = {}
        params.update(IDP_PARAMS)
        params.update(REQUEST_PARAMS)
        params.update(RESPONSE_PARAMS)
        params['ASSERTION'] = ASSERTION_SALESFORCE_XML
        self._test_template(RESPONSE, params, RESPONSE_XML)

    def test_response_rendering(self):
        # Verifies that the rendering is OK.
        params = {}
        params.update(IDP_PARAMS)
        params.update(REQUEST_PARAMS)
        params.update(RESPONSE_PARAMS)
        params['ASSERTION'] = ASSERTION_SALESFORCE_XML
        got = xml_render.get_response_xml(params, signed=False)
        self._test(got, RESPONSE_XML)

    def test_response_with_signed_assertion(self):
        # This test also verifies that the template isn't bad.
        params = {}
        params.update(IDP_PARAMS)
        params.update(REQUEST_PARAMS)
        params.update(RESPONSE_PARAMS)
        params['ASSERTION'] = SIGNED_ASSERTION_SALESFORCE_XML
        got = xml_render.get_response_xml(params, signed=False)
        self._test(got, RESPONSE_WITH_SIGNED_ASSERTION_SALESFORCE_XML)

    def test_signed_response_with_signed_assertion(self):
        # This test verifies that the response got signed properly.
        params = {}
        params.update(IDP_PARAMS)
        params.update(REQUEST_PARAMS)
        params.update(RESPONSE_PARAMS)
        params['ASSERTION'] = SIGNED_ASSERTION_SALESFORCE_XML
        got = xml_render.get_response_xml(params, signed=True)
        self._test(got, SIGNED_RESPONSE_WITH_SIGNED_ASSERTION_SALESFORCE_XML)
