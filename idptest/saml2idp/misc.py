"""
Miscellaneous methods that should be elsewhere eventually.
"""
from xml.dom import minidom
from xml.dom.ext import c14n
from BeautifulSoup import BeautifulStoneSoup

def canonicalize_pyxml(xml):
    """ Returns Canonicalized XML. """
    doc = minidom.parseString(xml)
    canonicalized = c14n.Canonicalize(doc)
    return canonicalized

from StringIO import StringIO
from lxml import etree
def canonicalize_lxml(src):
    f = StringIO(src)
    tree = etree.parse(f)
    f2 = StringIO()
    tree.write_c14n(f2)
    return f2.getvalue().decode("utf-8")

canonicalize = canonicalize_lxml

def ws_strip(src):
    """
    Returns src stripped of blank lines that result from Django's templates.
    """
    stripped = '\n'.join( [
        line for line in src.split('\n') if line.strip() != ''
    ] )
    return stripped

def get_acs_url(assertion_xml):
    """
    Returns the value of the AssertionConsumerServiceURL attribute.
    NOTE: This should be part of the underlying SAML library, probably.
    """
    #XXX: This is a horrible hack. It could be more elegant.
    soup = BeautifulStoneSoup(assertion_xml)
    url = soup.findAll()[0]['assertionconsumerserviceurl']
    return url
