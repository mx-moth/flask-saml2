"""
Tests of samltags template tags library.
"""
from django.test import TestCase
from django.template import Context, Template
from saml2idp.templatetags.samltags import assertion_xml
from BeautifulSoup import BeautifulStoneSoup
import zlib

class TestAssertionXML(TestCase):
    def test(self):
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
        t = Template(
            '{% load samltags %}'
            '{% assertion_xml saml_request assertion %}'
        )
        c = Context({
            'saml_request': saml_request,
            'assertion': assertion,
        })
        src = t.render(c)
        got = src #zlib.compress(src) #BeautifulStoneSoup(src).prettify()


        f = open('saml2idp/tests/expected/assertion1.xml', 'r')
        src = f.read()
        exp = src #zlib.compress(src) #BeautifulStoneSoup(src).prettify()
        f.close()

        g = open('saml2idp/tests/expected/assertion1.got.xml', 'w')
        g.write(got)
        g.close()
        msg = "Did not get expected XML. See ${filename}."
        self.assertEqual(got, exp, msg)
