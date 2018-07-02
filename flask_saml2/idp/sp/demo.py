from flask_saml2.idp import processor, xml_render


class Processor(processor.Processor):
    """
    Demo Response Handler Processor for testing against django-saml2-sp.
    """
    def format_assertion(self):
        # NOTE: This uses the SalesForce assertion for the demo.
        self.assertion_xml = xml_render.get_assertion_salesforce_xml(
            self.assertion_params, signed=True)


class AttributeProcessor(Processor):
    """
    Demo Response Handler Processor for testing against django-saml2-sp;
    Adds SAML attributes to the assertion.
    """
    def build_assertion(self):
        super().build_assertion()
        self.assertion_params['ATTRIBUTES'] = {
            'foo': 'bar',
        }
