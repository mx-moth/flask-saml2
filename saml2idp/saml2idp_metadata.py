"""
Django Settings that more closely resemble SAML Metadata.

Detailed discussion is in doc/SETTINGS_AND_METADATA.txt.
"""
from django.conf import settings
from django.core.exceptions import ImproperlyConfigured

CERTIFICATE_DATA = 'certificate_data'
CERTIFICATE_FILENAME = 'certificate_file'
PRIVATE_KEY_DATA = 'private_key_data'
PRIVATE_KEY_FILENAME = 'private_key_file'


def check_configuration_contains(config, keys):
    available_keys = frozenset(keys).intersection(frozenset(config.keys()))

    if not available_keys:
        raise ImproperlyConfigured(
            'one of the following keys is required but none was '
            'specified: {}'.format(keys))

    if len(available_keys) > 1:
        raise ImproperlyConfigured(
            'found conflicting configuration: {}. Only one key can be used at'
            'a time.'.format(available_keys))


def validate_configuration(config):
    check_configuration_contains(config=config,
                                 keys=(PRIVATE_KEY_DATA, PRIVATE_KEY_FILENAME))

    check_configuration_contains(config=config,
                                 keys=(CERTIFICATE_DATA, CERTIFICATE_FILENAME))


try:
    SAML2IDP_CONFIG = settings.SAML2IDP_CONFIG
except:
    raise ImproperlyConfigured('SAML2IDP_CONFIG setting is missing.')
else:
    validate_configuration(SAML2IDP_CONFIG)

try:
    SAML2IDP_REMOTES = settings.SAML2IDP_REMOTES
except:
    raise ImproperlyConfigured('SAML2IDP_REMOTES setting is missing.')
