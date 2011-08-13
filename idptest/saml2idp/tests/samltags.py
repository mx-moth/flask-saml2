"""
Tests of samltags template tags library.
"""
from django.conf import settings
from django.test import TestCase
from django.template import Context, Template
from saml2idp.templatetags.samltags import assertion_xml
from saml2idp import signing
from saml2idp.misc import canonicalize, ws_strip

# Always use our sample keys for testing.
TEST_KEY = settings.PROJECT_ROOT + '/keys/sample/sample-private-key.pem'
TEST_CERT = settings.PROJECT_ROOT + '/keys/sample/sample-certificate.pem'

TESTDATAPATH = 'saml2idp/tests/data/'

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

# Sign stuff.
signer = signing.Signer(TEST_KEY, TEST_CERT)
signed_assertion = dict(assertion.items()) # deepcopy
signed_assertion['signature'] = signer.get_assertion_signature(saml_request, assertion, issuer)
signature = signer.get_response_signature(saml_request, saml_response, signed_assertion, issuer)

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
        got = canonicalize(ws_strip(template.render(context)))

        # (Post-act?) Save "gotten" XML, for use with external diff tools.
        gotfilename = TESTDATAPATH + expfile + '.got.xml'
        g = open(gotfilename, 'w')
        g.write(got)
        g.close()

        # (Pre-assert?) Load expected XML from file.
        expfilename = TESTDATAPATH + expfile + '.xml'
        f = open(expfilename, 'r')
        exp = canonicalize(f.read())
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

    def test_assertion_with_signature(self):
        self._test('assertion_with_signature',
                   saml_request, signed_assertion, issuer)


class TestResponseBase(TestXML):
    """
    Tests for the entire Response.
    """
    def _test(self, expfile, req, resp, asrt, issr=None, sign=None):
        # Arrange.
        t = Template(
            '{% load samltags %}'
            '{% response_xml saml_request saml_response assertion issuer signature %}'
        )
        c = Context({
            'saml_request': req,
            'saml_response': resp,
            'assertion': asrt,
            'issuer': issr,
            'signature': sign,

        })
        self._test_base(expfile, t, c)


class TestResponseXML(TestResponseBase):
    def test_response_simple(self):
        self._test('response_simple', saml_request, saml_response, assertion)

    def test_response_with_signature(self):
        self._test('response_with_signature', saml_request, saml_response,
                   signed_assertion, issuer, signature)


class TestReferenceXML(TestResponseBase):
    """ Compare with known, working references. """
    def test_response_from_php(self):
        """ Compare with SimpleSAMLphp reference. """
        php_request = {
            'id': 'mpjibjdppiodcpciaefmdahiipjpcghdcfjodkbi',
            'acs_url': 'https://www.google.com/a/abrickaday.com/acs',
            'audience': 'google.com',
        }
        php_response = {
            'id': '_2972e82c07bb5453956cc11fb19cad97ed26ff8bb4',
            'issue_instant': '2011-08-11T23:38:34Z',
        }
        php_assertion = {
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
        php_issuer = 'http://127.0.0.1/simplesaml/saml2/idp/metadata.php'

        # Sign things.
        php_signer = signing.Signer(TESTDATAPATH + 'php-private-key.pem',
            TESTDATAPATH + 'php-certificate.pem')
        #print php_signer.get_certificate()

        signed_php_assertion = dict(php_assertion.items()) # deepcopy
        asig = php_signer.get_assertion_signature(php_request, php_assertion, php_issuer)
        signed_php_assertion['signature'] = asig

        rsig = php_signer.get_response_signature(
                    php_request, php_response,
                    signed_php_assertion, php_issuer)

        self._test('response_from_php', php_request, php_response,
                    signed_php_assertion, php_issuer, rsig)


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
