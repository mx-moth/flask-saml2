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
        links = get_links(config)
        for name, pattern in links:
            if name == resource_name:
                return config
    msg = 'SAML2IDP_REMOTES is not configured to handle a link resource "%s"'
    raise ImproperlyConfigured(msg % resource_name)

def get_deeplink_resources():
    """
    Returns a list of resources that can be used for deep-linking.
    """
    resources = []
    for key, sp_config in SAML2IDP_REMOTES.items():
        links = get_links(sp_config)
        for resource, patterns in links:
            if '/' not in resource:
                # It's a simple deeplink, which is handled by 'login_init' URL.
                continue
            resources.append(resource)
    return resources

def get_links(sp_config):
    """
    Returns a list of (resource, pattern) tuples for the 'links' for an sp.
    """
    links = sp_config.get('links', [])
    if type(links) is dict:
        links = links.items()
    return links
