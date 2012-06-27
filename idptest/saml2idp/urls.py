from django.conf.urls.defaults import *
from views import descriptor, login_begin, login_init, login_process, logout

urlpatterns = patterns('',
   url( r'^init/(?P<resource>\w+)/(?P<target>\w+)/$', login_init, name="login_init"),
   url( r'^login/$', login_begin, name="login_begin"),
   url( r'^login/process/$', login_process, name='login_process'),
   url( r'^logout/$', logout, name="logout"),
    (r'^metadata/xml/$', descriptor),
)
