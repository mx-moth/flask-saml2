.. module:: flask_saml2.idp

==================
Identity providers
==================

When users need to authenticate themselves with a Service Provider (SP),
the SP will redirect the user to an Identity Provider (IdP).
The users will authenticate with the Identity Provider,
and will be redirected back to the Service Provider with a payload that identifies the user.

Flask SAML2 implements all parts of the IdP workflow,
except for authenticating your users against your user database
(or however your users are managed).
Developers should create an :class:`IdentityProvider` subclass for their application
that integrates with some other form of authentication,
such as `Flask-Login <https://github.com/maxcountryman/flask-login>`_.
Once a user is authenticated with the IdP,
relevant user details will be composed into a payload
which will be sent via the users browser back to the SP.

The method :meth:`IdentityProvider.create_blueprint` generates a Flask :class:`~flask.Blueprint`,
which needs to be registered in your application
via :meth:`app.register_blueprint(idp.create_blueprint()) <flask.Flask.register_blueprint>`.

Any Service Providers the IdP handles need to be registered as well.
These will be instances of :class:`SPHandler`.

An functional example IdP and Flask application that uses a static list of users
can be found in the ``examples/`` directory of the repository.

.. toctree::

    identityprovider
    sphandler
    configuration
