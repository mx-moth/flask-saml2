"""
Query metadata from settings.
"""
# Django imports
from django.core.exceptions import ImproperlyConfigured
# Local imports
from saml2idp_metadata import SAML2IDP_CONFIG, SAML2IDP_REMOTES

def get_config_for_acs(acs_url):
    """
    Return SP configuration instance that handles acs_url.
    """
    for friendlyname, config in SAML2IDP_REMOTES.items():
        if config['acs_url'] == acs_url:
            return config
    msg = 'SAML2IDP_REMOTES is not configured to handle the AssertionConsumerService at "%s"'
    raise ImproperlyConfigured(msg % resource_name)

def get_config_for_resource(resource_name):
    """
    Return the SP configuration that handles a deep-link resource_name.
    """
    for friendlyname, config in SAML2IDP_REMOTES.items():
        links = config.get('links', {})
        for name, pattern in links.items():
            if name == resource_name:
                return config
    msg = 'SAML2IDP_REMOTES is not configured to handle a link resource "%s"'
    raise ImproperlyConfigured(msg % resource_name)
