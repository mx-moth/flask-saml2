from django.conf.urls.defaults import *
from views import saml_assert

urlpatterns = patterns('',
   ('^saml/assert/$',  saml_assert),
)
