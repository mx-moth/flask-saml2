.. install

==========
Installing
==========

Install ``flask-saml2`` using pip:

.. code-block:: sh

    $ pip install flask-saml2

Dependencies
============

``flask-saml2`` relies on some libraries that have external dependencies.
These external dependencies must be installed
before ``flask_saml2`` and it's dependencies can be installed.

OpenSSL
-------

``flask-saml2`` relies on the :doc:`pyopenssl <OpenSSL:index>` library,
which requires the ``openssl`` library to be installed.
Please consult the documentation on :doc:`installing pyopenssl <OpenSSL:install>`
for installation requirements.

lxml
----

``flask-saml2`` relies on `lxml <https://lxml.de/>`_.
Please consult the `Installing lxml <https://lxml.de/installation.html>`_
and install all of the external dependencies for ``lxml``
before installing ``flask-saml2``.
