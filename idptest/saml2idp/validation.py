"""
Validations for various conditions; or place-holders for future enhancement.
These methods should return nothing for success and raise an exception on
invalid conditions. (I think.)
"""
from saml2idp_settings import SAML2IDP_VALID_ACS

def validate_request(authn_req):
    acs_url = authn_req['ACS_URL']
    assert acs_url in SAML2IDP_VALID_ACS, "ACS url '%s' not specified in SAML2IDP_VALID_ACS setting." % acs_url

def validate_user(request):
    """
    Stub. If you need per-user validation beyond simple authentication, then
    create a method with this signature and pass it into login_continue()
    as the 'validate_user_function' optional parameter.
    """
    pass
