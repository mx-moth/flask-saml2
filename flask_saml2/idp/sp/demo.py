from flask_saml2.idp import sphandler
from flask_saml2.xml_templates import XmlTemplate

from .salesforce import get_assertion_xml


class SPHandler(sphandler.SPHandler):
    """
    Demo Response Handler SPHandler for testing against django-saml2-sp.
    """
    def format_assertion(self, assertion_params: dict) -> XmlTemplate:
        # NOTE: This uses the SalesForce assertion for the demo.
        return get_assertion_xml(
            parameters=assertion_params,
            certificate=self.idp.get_idp_certificate(),
            signer=self.idp.get_idp_signer(),
            digester=self.idp.get_idp_digester())


class AttributeSPHandler(SPHandler):
    """
    Demo Response Handler SPHandler for testing against django-saml2-sp;
    Adds SAML attributes to the assertion.
    """
    def build_assertion(self, request):
        return {
            **super().build_assertion(request),
            'ATTRIBUTES': {
                'foo': 'bar',
            },
        }
