"""
Django Settings that more closely resemble SAML Metadata.

Detailed discussion is in doc/SETTINGS_AND_METADATA.txt.
"""
__all__ = [ 'SAML2IDP_CONFIG', 'SAML2IDP_REMOTES' ]
from django.conf import settings
from django.core.exceptions import ImproperlyConfigured

try:
    SAML2IDP_CONFIG = settings.SAML2IDP_CONFIG
except:
    raise ImproperlyConfigured('SAML2IDP_CONFIG setting is missing.')

try:
    SAML2IDP_REMOTES = settings.SAML2IDP_REMOTES
except:
    raise ImproperlyConfigured('SAML2IDP_REMOTES setting is missing.')
