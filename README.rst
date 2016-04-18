dj-saml-idp
===========

.. image:: https://travis-ci.org/mobify/dj-saml-idp.svg?branch=master
    :target: https://travis-ci.org/mobify/dj-saml-idp


This is a fork `novapost/django-saml2-idp`_ that is distributed indipendantly as `dj-saml-idp`.

`dj-saml-idp` implements the Identity Provider side of the SAML 2.0 protocol
and makes user authentication available to external applications.

**Note:** Only supports Django 1.5+.


Testing 
-------

The test runner is `pytest` and we are using `tox` to run tests against
different versions of Django. The test can be run locally using either `tox`
directly (preferably in a virtualenv)::

    $ pip install tox
    $ tox

Or inside a Docker container using using the provided `Dockerfile` and with 
docker-compose (requires `docker` and `docker-compose` to be installed)::

    $ docker-compose run test-27


Release
-------

First of all, create a new version of the package. We use `bumpversion`_ to
handle updating all version strings, committing the changes and creating a
new git tag automatically. To bump the packag version use the follwoing
command with whichever part of the semantic version you'd like to update::

    $ bumpversion (major|minor|patch)

for instance for a *minor* update, use (which should be the most common case)::

    $ bumpersion minor

You need the PyPI credentials for the `mobify` account to be able to release
a new version and the build script is expecting it defined as an environment
variable::

    $ export PYPI_PASSWORD=supersecretpassword

Releasing a new version to PyPI is very simple. The first thing you need to do
is make sure that all the test are passing and that the version in
`saml2idp/__init__.py` is the one that you'd like to create on PyPI.

With that done, all you need to do is run the following commands::

    $ make release

This will cleanup the `build/` and `dist/` directories, build a source package
and a Python wheel. Both will then be uploaded to PyPI.


License
-------

Distributed under the `MIT License`_.


.. _`novapost/django-saml2-idp`: https://github.com/novapost/django-saml2-idp
.. _`MIT License`: https://github.com/mobify/dj-saml-idp/blob/master/LICENSE
.. _`wheel`: http://wheel.readthedocs.org/en/latest/
.. _`bumpversion`: https://github.com/peritus/bumpversion
