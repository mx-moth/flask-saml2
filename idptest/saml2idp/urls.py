from django.conf.urls.defaults import *
from views import SAML_assert

urlpatterns = patterns('',
   ('^saml/assert/$',  SAML_assert),
)
