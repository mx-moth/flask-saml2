dj-saml-idp
===========

.. image:: https://travis-ci.org/timheap/flask-saml2-idp.svg?branch=master
    :target: https://travis-ci.org/timheap/flask-saml2-idp


This is a fork of `NoodleMarkets/dj-saml-idp`_ which in turn is a fork of
`deforestg/dj-saml-idp`_ which in turn is a fork of
`novapost/django-saml2-idp`_.

This fork provides a SAML 2.0 IdP application for Flask and Python 3.

`flask-saml2-idp` implements the Identity Provider side of the SAML 2.0 protocol
and makes user authentication available to external applications.

**Note:** Only targets support of Python 3.5+ and Flask 1.0+

Testing
-------

The test runner is `pytest` and we are using `tox` to run tests against
different versions of Flask and Python. The test can be run locally using
either `tox` directly (preferably in a virtualenv)::

    $ pip install tox
    $ tox

License
-------

Distributed under the `MIT License`_.

.. _`NoodleMarkets/dj-saml-idp`: https://github.com/NoodleMarkets/dj-saml-idp
.. _`deforestg/dj-saml-idp`: https://github.com/deforestg/dj-saml-idp
.. _`novapost/django-saml2-idp`: https://github.com/novapost/django-saml2-idp
.. _`MIT License`: https://github.com/mobify/dj-saml-idp/blob/master/LICENSE
.. _`wheel`: http://wheel.readthedocs.org/en/latest/
.. _`bumpversion`: https://github.com/peritus/bumpversion
