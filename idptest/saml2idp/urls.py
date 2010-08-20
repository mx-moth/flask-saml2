from django.conf.urls.defaults import *
from views import sso_handle_incoming_post_request, sso_post_response
# For testing SAML output:
from views import saml_assert

urlpatterns = patterns('',
   ('^saml/assert/$',  saml_assert),
   ('^sso/post/request/$', sso_handle_incoming_post_request),
   ('^sso/post/response/$', sso_post_response),
)
