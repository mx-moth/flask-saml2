django-saml2-idp
================

Authenticate users for your Django web app against a SAML 2.0 Identity Provider.

This is a companion project to the Django SAML 2.0 Service Provider app @ http://github.com/novapost/django-saml2-sp/.

Run the demo sponsored by Anderson Innovative, LLC at https://idpdemo.andersoninnovative.com/. The demo is running code under tag "demo2".

Fork from http://django-saml2-idp.googlecode.com.

Notes
-----------------------

Supports Django 1.5.x.

Test Application
----------------------

The `idptest` is a reference implementation of the `saml2idp` application
(which can be found in `idptest/saml2idp`.).

You can test it by install `pip install -r requirements.txt`.

Additional Dependencies
-----------------------

Compling M2Crypto requires SWIG, and OpenSSL headers and libraries.

