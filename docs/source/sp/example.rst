=======
Example
=======

To make your application into a Service Provider,
create a :class:`ServiceProvider` subclass, instantiate it,
and register it's :class:`~flask.Blueprint`
with your :class:`Flask application <flask.Flask>`:

.. code-block:: python

    from flask import Flask
    from flask_saml2.sp import ServiceProvider


    class MyServiceProvider(ServiceProvider):
        def get_default_login_return_url(self):
            return url_for('dashboard')

        def get_logout_return_url(self):
            return url_for('index')

    sp = ServiceProvider()

    app = Flask()
    app.register_blueprint(sp.create_blueprint(), url_prefix='/saml/')
    app.run()
