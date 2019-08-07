.. examples_

========
Examples
========

The ``flask_saml2`` repository comes with an example implementation of
an Identity Provider and a Service Provider,
configured to work with one another.

To run the example implementation, clone the ``flask_saml2`` repository
and follow the instructions in the README.

The example uses a hard coded list of users in the Identity Provider.
A real implementation would most likely use an external user database,
with authentication perhaps managed by
`Flask-Login <https://github.com/maxcountryman/flask-login>`_.
