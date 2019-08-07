.. module:: flask_saml2.sp

=================
Service providers
=================

A Service Provider (SP) is a website that users visit,
that uses a separate Identity Provider (IdP) to authenticate users.

Flask SAML2 provides all of the functionality required to implement your own SP
that can authenticate using one or more external IdPs.
These IdPs can be written using :mod:`flask_saml2.idp`,
or come from external providers.

The method :meth:`ServiceProvider.create_blueprint` generates a Flask :class:`~flask.Blueprint`,
which needs to be registered in your application
via :meth:`app.register_blueprint(sp.create_blueprint()) <flask.Flask.register_blueprint>`.

Any Identity Providers the SP can authenticate with
need to be registered as well.
These will be instances of :class:`IdPHandler`.

An functional example SP and Flask application
can be found in the ``examples/`` directory of the repository.

.. toctree::

    serviceprovider
    idphandler
    configuration
    example
