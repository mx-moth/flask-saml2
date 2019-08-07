flask-saml2
===========

.. image:: https://travis-ci.com/timheap/flask-saml2.svg?branch=master
    :target: https://travis-ci.com/timheap/flask-saml2
.. image:: https://badge.fury.io/py/flask-saml2.svg
    :target: https://pypi.org/project/flask-saml2/
.. image:: https://readthedocs.org/projects/flask-saml2/badge/?version=latest
    :target: https://flask-saml2.readthedocs.io/en/latest/

This Flask plugin provides functionality for creating both SAML Service
Providers and Identity Providers. Applications can implement one or both of
these providers.

``flask-saml2`` works with Flask 1.0+ and Python 3.6+.

This is a heavily modified fork of `NoodleMarkets/dj-saml-idp`_ which in turn
is a fork of `deforestg/dj-saml-idp`_ which in turn is a fork of
`novapost/django-saml2-idp`_.

Terminology
-----------

For a full description of how SAML works, please seek guides elsewhere on the
internet. For a quick introduction, and a run through of some of the
terminology used in this package, read on.

The SAML protocal is a conversation between two parties:
**Identity Providers (IdP)** and **Service Providers (SP)**.
When an unauthenticated client (usually a browser) accesses a Service Provider,
the Service Provider will make an **authentication request (AuthnRequest)**,
sign it using its private key, and then forward this request via the client to
the Identity Provider. Once the client logs in at the central Identity
Provider, the Identity Provider makes a response, signs it, and forwards this
response via the client to the requesting Service Provider. The client is then
authenticated on the Service Provider via the central Identity Provider,
without the Service Provider having to know anything about the authentication
method, or any passwords involved.

Example implementations
-----------------------

A minimal but functional example implementation of both a Service Provider and
an Identity Provider can be found in the ``examples/`` directory of this
repository. To get the examples running, first clone the repository and install
the dependencies:

.. code-block:: console

    $ git clone https://github.com/timheap/flask-saml2
    $ cd flask-saml2
    $ python3 -m venv venv
    $ source venv/bin/activate
    $ pip install -e .
    $ pip install -r tests/requirements.txt

Next, run the IdP and the SP in separate terminal windows:

.. code-block:: console

    $ cd flask-saml2
    $ source venv/bin/activate
    $ ./examples/idp.py

.. code-block:: console

    $ cd flask-saml2
    $ source venv/bin/activate
    $ ./examples/sp.py

Finally, navigate to http://localhost:9000/ to access the Service Provider
landing page.

Testing
-------

The test runner is `pytest` and we are using `tox` to run tests against
different versions of Flask and Python. The test can be run locally using
`tox` directly (preferably in a virtual environment)::

    $ pip install tox
    $ tox

License
-------

Distributed under the `MIT License`_.

.. _`NoodleMarkets/dj-saml-idp`: https://github.com/NoodleMarkets/dj-saml-idp
.. _`deforestg/dj-saml-idp`: https://github.com/deforestg/dj-saml-idp
.. _`novapost/django-saml2-idp`: https://github.com/novapost/django-saml2-idp
.. _`MIT License`: https://github.com/mobify/dj-saml-idp/blob/master/LICENSE
