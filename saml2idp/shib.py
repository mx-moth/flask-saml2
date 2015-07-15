import base
import xml_render
import zlib
import base64


class Processor(base.Processor):
    """
    Shib-specific Processor
    """
    def _format_assertion(self):
        self._assertion_xml = xml_render.get_assertion_salesforce_xml(self._assertion_params, signed=True)

    def _decode_request(self):
        """
        Decodes _request_xml from _saml_request.
        """
        self._request_xml = zlib.decompress(base64.b64decode(self._saml_request), -15)

    def _determine_audience(self):
        """
        Determines the _audience.
        """
        self._audience = "https://sp.testshib.org/shibboleth-sp"
