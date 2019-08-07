import urllib.parse

from flask_saml2 import exceptions
from flask_saml2.idp import SPHandler, xml_templates


class GoogleAppsAssertionTemplate(xml_templates.AssertionTemplate):
    """
    .. code-block:: xml

        <saml:Assertion xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion"
                ID="${ASSERTION_ID}"
                IssueInstant="${ISSUE_INSTANT}"
                Version="2.0">
            <saml:Issuer>${ISSUER}</saml:Issuer>
            ${ASSERTION_SIGNATURE}
            ${SUBJECT_STATEMENT}
            <saml:Conditions NotBefore="${NOT_BEFORE}" NotOnOrAfter="${NOT_ON_OR_AFTER}"></saml:Conditions>
            <saml:AuthnStatement AuthnInstant="${AUTH_INSTANT}">
                <saml:AuthnContext>
                    <saml:AuthnContextClassRef>urn:oasis:names:tc:SAML:2.0:ac:classes:Password</saml:AuthnContextClassRef>
                </saml:AuthnContext>
            </saml:AuthnStatement>
            ${ATTRIBUTE_STATEMENT}
        </saml:Assertion>
    """

    namespace = 'saml'

    def _get_conditions(self):
        return self.element('Conditions', attrs={
            'NotBefore': self.params['NOT_BEFORE'],
            'NotOnOrAfter': self.params['NOT_ON_OR_AFTER'],
        })


class GoogleAppsSPHandler(SPHandler):
    """
    Google Apps :class:`SPHandler` implementation.
    """
    assertion_template = GoogleAppsAssertionTemplate

    def validate_request(self, request):
        url = urllib.parse.urlparse(request.acs_url)
        is_valid = url.netloc.endswith('.google.com') \
            and url.path.startswith('/a/') \
            and url.scheme in ('http', 'https')

        if not is_valid:
            raise exceptions.CannotHandleAssertion('AssertionConsumerService is not a Google Apps URL.')
