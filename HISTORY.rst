.. :changelog:


Release History
---------------


0.21.3
++++++

* Allow a `redirect_to` parameter to be passed to the logout view to redirect
  the user to after succesful logout instead of showing the logout page.
* Introduce logging through `structlog` and provide more informative logging
  out put to make SAML flows easier to debug. Log messages are all logged under
  the `saml2idp` logger now.


0.21.2 (2016-04-18)
+++++++++++++++++++


* Switched from `django.utils.importlib` to Python's standard `importlib` to
  work with Django 1.9.
* Update the test setup to run tests against Django 1.9 in addition to all
  other versions of Django.
