About SAML 2.0 Processors
-------------------------
A SAML 2.0 Processor is responsible for taking a SAML 2.0 AuthnRequest
and returning to SAML 2.0 Response.

Why not Middleware?
-------------------
Could this be done with middleware? Sure. But it's really only used by
the views in this app, and the interface of a Processor doesn't match that
of a Middleware class.
