import urllib.parse

from flask_saml2 import exceptions
from flask_saml2.idp import SPHandler


class SalesforceSPHandler(SPHandler):
    """
    Salesforce.com :class:`SPHandler` implementation.
    """

    def validate_request(self, request):
        url = urllib.parse.urlparse(request.acs_url)

        is_valid = url.netloc.endswith('.salesforce.com') and \
            url.scheme in ('http', 'https')

        if not is_valid:
            raise exceptions.CannotHandleAssertion('AssertionConsumerService is not a SalesForce URL.')

    def get_audience(self, request):
        return 'https://saml.salesforce.com'
