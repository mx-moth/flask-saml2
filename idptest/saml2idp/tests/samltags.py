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

class TestAssertionXML(TestCase):
    """
    Tests for the Assertion section only.
    """
    def _test(self, expfile, saml_request, assertion, issuer=None):
        """
        Renders the assertion using these parameters and compares it with
        expected xml from expfile.
        """
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

        # Act.
        got = t.render(c)

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

    def test_assertion_without_issuer(self):
        self._test('assertion_without_issuer', saml_request, assertion)

    def test_assertion_with_issuer(self):
        self._test('assertion_with_issuer', saml_request, assertion, issuer)
