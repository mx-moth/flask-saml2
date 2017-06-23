from django.contrib.auth import authenticate, login
import logging
log = logging.getLogger(__name__)


class LoginMiddleware(object):
    def process_request(self, request):
        if not request.user.is_authenticated():
            user = authenticate(username='admin', password='test')
            login(request=request, user=user)
