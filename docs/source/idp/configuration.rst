.. idp/configuration_
.. module:: flask_saml2.idp
    :noindex:

=============
Configuration
=============

The IdP needs two configuration options by default,
``SAML2_IDP`` and ``SAML2_SERVICE_PROVIDERS``.
``SAML2_IDP`` configures the IdP itself,
while ``SAML2_SERVICE_PROVIDERS`` specifies all the SPs this IdP supports.

.. code-block:: python

    from flask_saml2.utils import certificate_from_file, private_key_from_file

    SAML2_IDP = {
        'autosubmit': True,
        'certificate': certificate_from_file('keys/idp_certificate.pem'),
        'private_key': private_key_from_file('keys/idp_private_key.pem'),
    }

    SAML2_SERVICE_PROVIDERS = [
        {
            'CLASS': 'myapp.SPHandler',
            'OPTIONS': {
                'display_name': 'Example Service Provider',
                'entity_id': 'http://service.example.com/saml/metadata.xml',
                'acs_url': 'http://service.example.com/saml/acs/',
                'certificate': certificate_from_file('keys/example_sp_certificate.pem'),
            },
        },
    ]

``SAML2_IDP`` is documented in :meth:`IdentityProvider.get_idp_config`.

``SAML2_SERVICE_PROVIDERS`` is a list of SPs the IdP will authenticate users for.
Each SP is represented as a dict.
``CLASS`` is the dotted Python path to a :class:`SPHandler` subclass,
and ``OPTIONS`` is a dict of keyword arguments to its constructor.
Refer to :class:`SPHandler` for more information on constructor arguments.
