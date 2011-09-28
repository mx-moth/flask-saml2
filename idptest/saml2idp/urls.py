from django.conf.urls.defaults import *
from views import login_begin, login_process, logout

urlpatterns = patterns('',
   url( r'^login/$', login_begin, name="login_begin"),
   url( r'^login/process/$', login_process, name='login_process'),
   url( r'^logout/$', logout, name="logout"),
)
