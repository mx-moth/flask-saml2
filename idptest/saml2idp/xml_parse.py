"""
Parse data from SAML 2.0 XML.
"""
from BeautifulSoup import BeautifulStoneSoup

def parse_request(request_xml):
    """
    Returns various parameters from request_xml in a dict.
    """
    soup = BeautifulStoneSoup(request_xml)
    request = soup.findAll()[0]
    params = {}
    params['ACS_URL'] = request['assertionconsumerserviceurl']
    params['REQUEST_ID'] = request['id']
    params['DESTINATION'] = request.get('destination', '')
    params['PROVIDER_NAME'] = request.get('providername', '')
    return params
