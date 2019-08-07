.. sp/configuration_
.. module:: flask_saml2.sp
    :noindex:

=============
Configuration
=============

The SP needs two configuration options by default,
``SAML2_SP`` and ``SAML2_IDENTITY_PROVIDERS``.
``SAML2_SP`` configures the Service Provider itself,
while ``SAML2_IDENTITY_PROVIDERS`` specifies all the IdPs the SP can authenticate with.

.. code-block:: python

    from flask_saml2.utils import certificate_from_file, private_key_from_file

    SAML2_SP = {
        'certificate': certificate_from_file('keys/sp_certificate.pem'),
        'private_key': private_key_from_file('keys/sp_private_key.pem'),
    }

    SAML2_IDENTITY_PROVIDERS = [
        {
            'CLASS': 'myapp.IdPHandler',
            'OPTIONS': {
                'display_name': 'Example Identity Provider',
                'entity_id': 'https://idp.example.com/saml/metadata.xml',
                'sso_url': 'https://idp.example.com/saml/login/',
                'slo_url': 'https://idp.example.com/saml/logout/',
                'certificate': certificate_from_file('keys/idp_certificate.pem'),
            },
        },
    ]

``SAML2_SP`` is documented in :meth:`ServiceProvider.get_sp_config`.

``SAML2_IDENTITY_PROVIDERS`` is a list of IdPs the SP can use for authentication.
Each IdP is represented as a dict.
``CLASS`` is the dotted Python path to a :class:`IdPHandler` subclass,
and ``OPTIONS`` is a dict of keyword arguments to its constructor.
Refer to :class:`IdPHandler` for more information on constructor arguments.
