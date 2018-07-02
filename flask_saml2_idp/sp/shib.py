import base64
import zlib

from . import base, xml_render


class Processor(base.Processor):
    """
    Shib-specific Processor
    """
    def format_assertion(self):
        self.assertion_xml = xml_render.get_assertion_salesforce_xml(
            self.assertion_params, signed=True)

    def decode_request(self):
        """
        Decodes _request_xml from _saml_request.
        """
        self.request_xml = zlib.decompress(base64.b64decode(self._saml_request), -15)

    def get_audience(self):
        return "https://sp.testshib.org/shibboleth-sp"
