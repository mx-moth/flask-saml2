import base
import exceptions
import xml_render

class Processor(base.Processor):
    """
    Demo Response Handler Processor for testing against django-saml2-sp.
    """
    def _validate_request(self):
        """
        Validates the _saml_request. Sub-classes should override this and
        throw an Exception if the validation does not succeed.
        """
        super(Processor, self)._validate_request()
        if not 'http://127.0.0.1:9000' in self._request_params['ACS_URL']:
            raise exceptions.CannotHandleAssertion('AssertionConsumerService is not a Demo URL.')

#    def _determine_audience(self):
#        self._audience = 'https://saml.salesforce.com'

    def _format_assertion(self):
        # NOTE: This uses the SalesForce assertion for the demo.
        self._assertion_xml = xml_render.get_assertion_salesforce_xml(self._assertion_params, signed=True)
