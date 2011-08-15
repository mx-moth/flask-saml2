"""
Miscellaneous methods that should be elsewhere eventually.
"""
#from xml.dom import minidom
#from xml.dom.ext import c14n

#def canonicalize_pyxml(xml):
#    """ Returns Canonicalized XML. """
#    doc = minidom.parseString(xml)
#    canonicalized = c14n.Canonicalize(doc)
#    return canonicalized

from StringIO import StringIO
from lxml import etree
def canonicalize_lxml(src):
    f = StringIO(src)
    tree = etree.parse(f)
    f2 = StringIO()
    tree.write_c14n(f2)
    return f2.getvalue().decode("utf-8")

canonicalize = canonicalize_lxml

def strip_blank_lines(src):
    """
    Returns src stripped of blank lines that result from Django's templates.
    """
    stripped = '\n'.join( [
        line for line in src.split('\n') if line.strip() != ''
    ] )
    return stripped

def ws_strip(src):
    """
    Returns src stripped of whitespace and blank lines from Django's templates.
    """
    stripped = ''.join( [
        line.strip() for line in src.split('\n') if line.strip() != ''
    ] )
    return stripped

from BeautifulSoup import BeautifulStoneSoup
def get_acs_url(request_xml):
    """
    Returns the value of the AssertionConsumerServiceURL attribute.
    NOTE: This should be part of the underlying SAML library, probably.
    """
    #XXX: This is a horrible hack. It could be more elegant.
    soup = BeautifulStoneSoup(request_xml)
    url = soup.findAll()[0]['assertionconsumerserviceurl']
    return url

def parse_saml_request(request_xml):
    """
    Returns various attributes from request_xml.
    NOTE: This should be part of the underlying SAML library, probably.
    """
    #XXX: This is a horrible hack. It could be more elegant.
    soup = BeautifulStoneSoup(request_xml)
    request = soup.findAll()[0]
    tmp = {}
    tmp['ACS_URL'] = request['assertionconsumerserviceurl']
    tmp['request_id'] = request['id']
    return tmp
