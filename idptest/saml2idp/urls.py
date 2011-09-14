from django.conf.urls.defaults import *
from views import login, login_post, login_continue, logout

urlpatterns = patterns('',
   url( r'^login/$', login, name="login"),
   url( r'^login/post/$', login_post, name="login_post"),
   url( r'^login/continue/$', login_continue, name='login_continue'),
   url( r'^logout/$', logout, name="logout"),
)
