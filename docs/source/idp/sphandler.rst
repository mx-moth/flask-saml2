=========
SPHandler
=========

An :class:`flask_saml2.idp.IdentityProvider` handles requests from Service Providers
via :class:`flask_saml2.idp.SPHandler` instances.

See :doc:`configuration` for configuration options.

.. autoclass:: flask_saml2.idp.SPHandler
    :members:

Specific implementations
========================

.. module:: flask_saml2.idp.sp

Some handlers for common Service Providers have been bundled with this project:

.. module:: flask_saml2.idp.sp.salesforce
.. autoclass:: flask_saml2.idp.sp.salesforce.SalesforceSPHandler

.. module:: flask_saml2.idp.sp.google_apps
.. autoclass:: flask_saml2.idp.sp.google_apps.GoogleAppsSPHandler

.. module:: flask_saml2.idp.sp.dropbox
.. autoclass:: flask_saml2.idp.sp.dropbox.DropboxSPHandler
