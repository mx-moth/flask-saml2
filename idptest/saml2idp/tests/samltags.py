"""
Tests of samltags template tags library.
"""
from django.test import TestCase
from django.template import Context, Template
from saml2idp.templatetags.samltags import assertion_xml

EXPECTED_XML_FILENAME = 'saml2idp/tests/expected/%s.xml'

# "Constants" used for these tests.
saml_request = {
    'id': 'mpjibjdppiodcpciaefmdahiipjpcghdcfjodkbi',
    'acs_url': 'https://www.google.com/a/abrickaday.com/acs',
    'audience': 'google.com',
}

saml_response = {
    'id': '_2972e82c07bb5453956cc11fb19cad97ed26ff8bb4',
    'issue_instant': '2011-08-11T23:38:34Z',
}

assertion = {
    'id': '_7ccdda8bc6b328570c03b218d7521772998da45374',
    'issue_instant': '2011-08-11T23:38:34Z',
    'not_before': '2011-08-11T23:38:04Z',
    'not_on_or_after': '2011-08-11T23:43:34Z',
    'session': {
        'index': '_ee277dff4e2db138d25dfcea7ccdf1d1db9ddea3f5',
        'not_on_or_after': '2011-08-12T07:38:34Z',
    },
    'subject': { 'email': 'student@abrickaday.com' },
}

issuer = 'http://127.0.0.1/simplesaml/saml2/idp/metadata.php'

signature = {
    'reference_uri': '#_2972e82c07bb5453956cc11fb19cad97ed26ff8bb4',
    'digest': 'hI+IRHRPC77suriMAt4gVVCcQgc=',
    'value': 'JJObb8Wc37VgBpD1bxMm6pStovjiK7wbL9U/vI1f3aIjIZrtZ2XfwzZiXoDROS0Aov33lNhM9yypZepQJpRrABZoxhcpg03C0GBhyREBC2HtWvmMaA6GP5oiojPJ1VCF3ArECht1RSMISLak/YxqiP6vgnQfZkuiKcaA8vEpAsI=',
    'certificate': 'MIICgTCCAeoCCQCbOlrWDdX7FTANBgkqhkiG9w0BAQUFADCBhDELMAkGA1UEBhMCTk8xGDAWBgNVBAgTD0FuZHJlYXMgU29sYmVyZzEMMAoGA1UEBxMDRm9vMRAwDgYDVQQKEwdVTklORVRUMRgwFgYDVQQDEw9mZWlkZS5lcmxhbmcubm8xITAfBgkqhkiG9w0BCQEWEmFuZHJlYXNAdW5pbmV0dC5ubzAeFw0wNzA2MTUxMjAxMzVaFw0wNzA4MTQxMjAxMzVaMIGEMQswCQYDVQQGEwJOTzEYMBYGA1UECBMPQW5kcmVhcyBTb2xiZXJnMQwwCgYDVQQHEwNGb28xEDAOBgNVBAoTB1VOSU5FVFQxGDAWBgNVBAMTD2ZlaWRlLmVybGFuZy5ubzEhMB8GCSqGSIb3DQEJARYSYW5kcmVhc0B1bmluZXR0Lm5vMIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQDivbhR7P516x/S3BqKxupQe0LONoliupiBOesCO3SHbDrl3+q9IbfnfmE04rNuMcPsIxB161TdDpIesLCn7c8aPHISKOtPlAeTZSnb8QAu7aRjZq3+PbrP5uW3TcfCGPtKTytHOge/OlJbo078dVhXQ14d1EDwXJW1rRXuUt4C8QIDAQABMA0GCSqGSIb3DQEBBQUAA4GBACDVfp86HObqY+e8BUoWQ9+VMQx1ASDohBjwOsg2WykUqRXF+dLfcUH9dWR63CtZIKFDbStNomPnQz7nbK+onygwBspVEbnHuUihZq3ZUdmumQqCw4Uvs/1Uvq3orOo/WJVhTyvLgFVK2QarQ4/67OZfHd7R+POBXhophSMv1ZOo',
}

class TestXML(TestCase):
    """
    Base class for XML TestCases.
    """
    def _test_base(self, expfile, template, context):
        """
        Renders the template using the context and compares it with
        expected xml from expfile.
        """
        # Arrange - done in sub-classes.

        # Act.
        got = template.render(context)

        # (Post-act?) Save "gotten" XML, for use with external diff tools.
        gotfilename = EXPECTED_XML_FILENAME % (expfile + '.got')
        g = open(gotfilename, 'w')
        g.write(got)
        g.close()

        # (Pre-assert?) Load expected XML from file.
        expfilename = EXPECTED_XML_FILENAME % expfile
        f = open(expfilename, 'r')
        exp = f.read()
        f.close()

        # Assert.
        msg = "Did not get expected XML. See %s." % gotfilename
        self.assertEqual(got, exp, msg)


class TestAssertionXML(TestXML):
    """
    Tests for the Assertion section only.
    """
    def _test(self, expfile, saml_request, assertion, issuer=None):
        # Arrange.
        t = Template(
            '{% load samltags %}'
            '{% assertion_xml saml_request assertion issuer %}'
        )
        c = Context({
            'saml_request': saml_request,
            'assertion': assertion,
            'issuer': issuer,
        })
        self._test_base(expfile, t, c)

    def test_assertion_without_issuer(self):
        self._test('assertion_without_issuer', saml_request, assertion)

    def test_assertion_with_issuer(self):
        self._test('assertion_with_issuer', saml_request, assertion, issuer)

class TestResponseXML(TestXML):
    """
    Tests for the entire Response.
    """
    def _test(self, expfile, saml_request, saml_response, assertion, issuer=None, signature=None):
        # Arrange.
        t = Template(
            '{% load samltags %}'
            '{% response_xml saml_request saml_response assertion issuer signature %}'
        )
        c = Context({
            'saml_request': saml_request,
            'saml_response': saml_response,
            'assertion': assertion,
            'issuer': issuer,
            'signature': signature,

        })
        self._test_base(expfile, t, c)

    def test_response_simple(self):
        self._test("response_simple", saml_request, saml_response, assertion)

class TestSignatureXML(TestXML):
    """
    Tests for the Signature section only.
    """
    def _test(self, expfile, signature):
        # Arrange.
        t = Template(
            '{% load samltags %}'
            '{% signature_xml signature %}'
        )
        c = Context({
            'signature': signature,
        })
        self._test_base(expfile, t, c)

    def test_signature(self):
        self._test("signature", signature)
