from django.conf import settings

try:
    #TODO: Some SAML Requestors may disallow this?
    SAML2IDP_AUTOSUBMIT = settings.SAML2IDP_AUTOSUBMIT
except:
    SAML2IDP_AUTOSUBMIT = True

try:
    SAML2IDP_ISSUER = settings.SAML2IDP_ISSUER
except:
    SAML2IDP_ISSUER = 'http://127.0.0.1:8000'

# If using relative paths, be careful!
try:
    SAML2IDP_CERTIFICATE_FILE = settings.SAML2IDP_CERTIFICATE_FILE
except:
    SAML2IDP_CERTIFICATE_FILE = 'keys/certificate.pem'

# If using relative paths, be careful!
try:
    SAML2IDP_PRIVATE_KEY_FILE = settings.SAML2IDP_PRIVATE_KEY_FILE
except:
    SAML2IDP_PRIVATE_KEY_FILE = 'keys/private-key.pem'

try:
    SAML2IDP_SIGNING = settings.SAML2IDP_SIGNING
except:
    SAML2IDP_SIGNING = True # by default

try:
    SAML2IDP_VALID_ACS = settings.SAML2IDP_VALID_ACS
except:
    #NOTE: If this is empty, SAML2IDP will be effectively disabled.
    # For Google Apps, you need to add something like this for your domain:
    #   'https://www.google.com/a/example.com/acs'
    # For SalesForce, this generic login will work for developer accounts;
    # you will likely need to update it with your production ACS URL.
    SAML2IDP_VALID_ACS = [
        'https://login.salesforce.com',
    ]

try:
    SAML2IDP_PROCESSOR_CLASSES = settings.SAML2IDP_PROCESSOR_CLASSES
except:
    SAML2IDP_PROCESSOR_CLASSES = [
        'saml2idp.salesforce.Processor',
        'saml2idp.google_apps.Processor',
    ]
