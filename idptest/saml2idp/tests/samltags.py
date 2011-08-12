"""
Tests of samltags template tags library.
"""
from django.conf import settings
from django.test import TestCase
from django.template import Context, Template
from saml2idp.templatetags.samltags import assertion_xml
from saml2idp import signing

# Always use our sample keys for testing.
TEST_KEY = settings.PROJECT_ROOT + '/keys/sample/sample-private-key.pem'
TEST_CERT = settings.PROJECT_ROOT + '/keys/sample/sample-certificate.pem'

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

def get_assertion_signature():
    """
    Returns a signature for the (unsigned) assertion.
    """
    t = Template(
        '{% load samltags %}'
        '{% assertion_xml saml_request assertion issuer %}'
    )
    c = Context({
        'saml_request': saml_request,
        'assertion': assertion,
        'issuer': issuer,
    })
    unsigned = t.render(c)
    signer = signing.Signer(TEST_KEY, TEST_CERT)
    digest, value, cert = signer.get_signature(unsigned)
    signature = ( {
        'reference_uri': assertion['id'],
        'digest': digest,
        'value': value,
        'certificate': cert,
    } )
    return signature

def get_signature():
    """
    Returns a signature for the entire (unsigned) response.
    """
    t = Template(
        '{% load samltags %}'
        '{% response_xml saml_request saml_response assertion issuer %}'
    )
    c = Context({
        'saml_request': saml_request,
        'saml_response': saml_response,
        'assertion': assertion,
        'issuer': issuer,
    })
    unsigned = t.render(c)
    signer = signing.Signer(TEST_KEY, TEST_CERT)
    digest, value, cert = signer.get_signature(unsigned)
    signature = ( {
        'reference_uri': saml_response['id'],
        'digest': digest,
        'value': value,
        'certificate': cert,
    } )
    return signature

signature = get_signature()
signed_assertion = dict(assertion.items()) # deepcopy
signed_assertion['signature'] = get_assertion_signature()

def ws_strip(src):
    """
    Returns src stripped of leading and trailing whitespace and blank lines.
    """
    stripped = '\n'.join( [
        line.strip() for line in src.split('\n') if line.strip() != ''
    ] )
    return stripped

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
        self.assertEqual(ws_strip(got), ws_strip(exp), msg)


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

    def test_assertion_with_signature(self):
        self._test('assertion_with_signature',
                   saml_request, signed_assertion, issuer)


class TestResponseXML(TestXML):
    """
    Tests for the entire Response.
    """
    def _test(self, expfile, saml_request, saml_response, assertion,
                    issuer=None, signature=None):
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

    def test_response_with_signature(self):
        self._test('response_with_signature', saml_request, saml_response,
                   signed_assertion, issuer, signature)


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
