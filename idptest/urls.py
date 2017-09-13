from django.conf.urls import include, url
from django.contrib.auth.views import LoginView
import saml2idp.urls

# Uncomment the next two lines to enable the admin:
from django.contrib import admin
admin.autodiscover()

urlpatterns = [
    url(r'^admin/', include(admin.site.urls)),

    # Required for login:
    url(r'^accounts/login/$', LoginView),

    # URLs for the IDP:
    url(r'^idp/', include(saml2idp.urls)),
]
