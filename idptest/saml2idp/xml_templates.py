"""
XML string templates for SAML 2.0

NOTE #1: OK, encoding XML into python is not optimal.
    However, this is the easiest way to get canonical XML...
    ...at least, without requiring other XML-munging libraries.
    I'm not including the indentation in the XML itself, because that messes
    with its canonicalization. This is meant to produce one long one-liner.
    I am indenting each line in python, for my own happiness. :)

NOTE #2: I'm using string.Template, rather than Django Templates, to avoid
    the overhead of loading Django's template code. (KISS, baby.)
"""
SIGNED_INFO = (
    '<ds:SignedInfo xmlns:ds="http://www.w3.org/2000/09/xmldsig#">'
        '<ds:CanonicalizationMethod Algorithm="http://www.w3.org/2001/10/xml-exc-c14n#"></ds:CanonicalizationMethod>'
        '<ds:SignatureMethod Algorithm="http://www.w3.org/2000/09/xmldsig#rsa-sha1"></ds:SignatureMethod>'
        '<ds:Reference URI="#${REFERENCE_URI}">'
            '<ds:Transforms>'
                '<ds:Transform Algorithm="http://www.w3.org/2000/09/xmldsig#enveloped-signature"></ds:Transform>'
                '<ds:Transform Algorithm="http://www.w3.org/2001/10/xml-exc-c14n#"></ds:Transform>'
            '</ds:Transforms>'
            '<ds:DigestMethod Algorithm="http://www.w3.org/2000/09/xmldsig#sha1"></ds:DigestMethod>'
            '<ds:DigestValue>${SUBJECT_DIGEST}</ds:DigestValue>'
        '</ds:Reference>'
    '</ds:SignedInfo>'
)
SIGNATURE = (
    '<ds:Signature xmlns:ds="http://www.w3.org/2000/09/xmldsig#">'
        '${SIGNED_INFO}'
    '<ds:SignatureValue>${RSA_SIGNATURE}</ds:SignatureValue>'
    '<ds:KeyInfo>'
        '<ds:X509Data>'
            '<ds:X509Certificate>${CERTIFICATE}</ds:X509Certificate>'
        '</ds:X509Data>'
    '</ds:KeyInfo>'
'</ds:Signature>'
)

# Minimal assertion for Google Apps:
ASSERTION_GOOGLE_APPS = (
    '<saml:Assertion xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion" '
            'ID="${ASSERTION_ID}" '
            'IssueInstant="${ISSUE_INSTANT}" '
            'Version="2.0">'
        '<saml:Issuer>${ISSUER}</saml:Issuer>'
        '${ASSERTION_SIGNATURE}'
        '<saml:Subject>'
            '<saml:NameID Format="${SUBJECT_FORMAT}" SPNameQualifier="${SP_NAME_QUALIFIER}">'
            '${SUBJECT}'
            '</saml:NameID>'
            '<saml:SubjectConfirmation Method="urn:oasis:names:tc:SAML:2.0:cm:bearer">'
                '<saml:SubjectConfirmationData '
                'InResponseTo="${REQUEST_ID}" '
                'NotOnOrAfter="${NOT_ON_OR_AFTER}" Recipient="${ACS_URL}"></saml:SubjectConfirmationData>'
            '</saml:SubjectConfirmation>'
        '</saml:Subject>'
        '<saml:Conditions NotBefore="${NOT_BEFORE}" NotOnOrAfter="${NOT_ON_OR_AFTER}">'
        '</saml:Conditions>'
        '<saml:AuthnStatement AuthnInstant="${AUTH_INSTANT}"'
            '>'
            '<saml:AuthnContext>'
                '<saml:AuthnContextClassRef>urn:oasis:names:tc:SAML:2.0:ac:classes:Password</saml:AuthnContextClassRef>'
            '</saml:AuthnContext>'
        '</saml:AuthnStatement>'
    '</saml:Assertion>'
)

# Minimal assertion for SalesForce:
ASSERTION_SALESFORCE = (
    '<saml:Assertion xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion" '
            'ID="${ASSERTION_ID}" '
            'IssueInstant="${ISSUE_INSTANT}" '
            'Version="2.0">'
        '<saml:Issuer>${ISSUER}</saml:Issuer>'
        '${ASSERTION_SIGNATURE}'
        '<saml:Subject>'
            '<saml:NameID Format="${SUBJECT_FORMAT}" SPNameQualifier="${SP_NAME_QUALIFIER}">'
            '${SUBJECT}'
            '</saml:NameID>'
            '<saml:SubjectConfirmation Method="urn:oasis:names:tc:SAML:2.0:cm:bearer">'
                '<saml:SubjectConfirmationData '
                'InResponseTo="${REQUEST_ID}" '
                'NotOnOrAfter="${NOT_ON_OR_AFTER}" Recipient="${ACS_URL}"></saml:SubjectConfirmationData>'
            '</saml:SubjectConfirmation>'
        '</saml:Subject>'
        '<saml:Conditions NotBefore="${NOT_BEFORE}" NotOnOrAfter="${NOT_ON_OR_AFTER}">'
            '<saml:AudienceRestriction>'
                '<saml:Audience>${AUDIENCE}</saml:Audience>'
            '</saml:AudienceRestriction>'
        '</saml:Conditions>'
        '<saml:AuthnStatement AuthnInstant="${AUTH_INSTANT}"'
            '>'
            '<saml:AuthnContext>'
                '<saml:AuthnContextClassRef>urn:oasis:names:tc:SAML:2.0:ac:classes:Password</saml:AuthnContextClassRef>'
            '</saml:AuthnContext>'
        '</saml:AuthnStatement>'
    '</saml:Assertion>'
)


# Minimal response:
RESPONSE = (
    '<samlp:Response xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol" '
                    'Destination="${ACS_URL}" '
                    'ID="${RESPONSE_ID}" '
                    'InResponseTo="${REQUEST_ID}" '
                    'IssueInstant="${ISSUE_INSTANT}" '
                    'Version="2.0">'
        '<saml:Issuer xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion">${ISSUER}</saml:Issuer>'
        '${RESPONSE_SIGNATURE}'
        '<samlp:Status>'
            '<samlp:StatusCode Value="urn:oasis:names:tc:SAML:2.0:status:Success"></samlp:StatusCode>'
        '</samlp:Status>'
        '${ASSERTION}'
    '</samlp:Response>'
)
