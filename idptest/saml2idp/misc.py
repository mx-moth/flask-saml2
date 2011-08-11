"""
Miscellaneous methods that should be elsewhere eventually.
"""
from BeautifulSoup import BeautifulStoneSoup

def get_acs_url(assertion_xml):
    """
    Returns the value of the AssertionConsumerServiceURL attribute.
    NOTE: This should be part of the underlying SAML library, probably.
    """
    #XXX: This is a horrible hack. It could be more elegant.
    soup = BeautifulStoneSoup(assertion_xml)
    url = soup.findAll()[0]['assertionconsumerserviceurl']
    return url
