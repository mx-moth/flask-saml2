"""
Tests for the demo AttributeProcessor and IdP-initiated deep-linking.
"""
# standard library imports:
import base64
# local imports:
import base

class TestDeepLink(base.SamlTestCase):
    SP_CONFIG = {
        'acs_url': 'http://127.0.0.1:9000/sp/acs/',
        'processor': 'saml2idp.demo.Processor',
        'links': {
            'deeplink': 'http://127.0.0.1:9000/sp/%s/',
        }
    }
    DEEPLINK = 'http://127.0.0.1:8000/idp/init/deeplink/test/'
    EXPECTED_RELAY_STATE = 'http://127.0.0.1:9000/sp/test/'

    def test_deeplink(self):
        # Arrange/Act:
        self._hit_saml_view(self.DEEPLINK)
        # Assert:
        #TODO: Use BeautifulSoup.
        self.assertTrue(self.EXPECTED_RELAY_STATE in self._html)

class TestDeepLinkWithAttributes(object): #DISABLED: base.SamlTestCase):
    SP_CONFIG = {
        'acs_url': 'http://127.0.0.1:9000/sp/acs/',
        'processor': 'saml2idp.demo.AttributeProcessor',
        'links': {
            'attr': 'http://127.0.0.1:9000/sp/%s/',
        },
    }
    DEEPLINK = 'http://127.0.0.1:8000/idp/init/attr/test/'
    EXPECTED_RELAY_STATE = 'http://127.0.0.1:9000/sp/test/'


#    def test_deeplink(self):
#        # Arrange: login new user.
#        self.client.login(username=self.USERNAME, password=self.PASSWORD)

#        # Act:
#        response = self.client.get(self.DEEPLINK, follow=True)
#        soup = BeautifulSoup(response.content)
#        inputtag = soup.findAll('input', {'name':'SAMLResponse'})[0]
#        encoded_response = inputtag['value']
#        samlresponse = codex.base64.b64decode(encoded_response)

#        # Assert:
#        self.assertTrue(self.EXPECTED_RELAY_STATE in samlresponse)
