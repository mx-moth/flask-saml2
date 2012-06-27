"""
Functions for creating XML output.
"""
import logging
import string
from xml_signing import get_signature_xml
from xml_templates import ATTRIBUTE, ATTRIBUTE_STATEMENT, \
    ASSERTION_GOOGLE_APPS, ASSERTION_SALESFORCE, RESPONSE, SUBJECT

def _get_attribute_statement(params):
    """
    Inserts AttributeStatement, if we have any attributes.
    Modifies the params dict.
    PRE-REQ: params['SUBJECT'] has already been created (usually by a call to
    _get_subject().
    """
    attributes = params.get('ATTRIBUTES', {})
    if len(attributes) < 1:
        params['ATTRIBUTE_STATEMENT'] = ''
        return
    # Build individual attribute list.
    template = string.Template(ATTRIBUTE)
    attr_list = []
    for name, value in attributes.items():
        subs = { 'ATTRIBUTE_NAME': name, 'ATTRIBUTE_VALUE': value }
        one = template.substitute(subs)
        attr_list.append(one)
    params['ATTRIBUTES'] = ''.join(attr_list)
    # Build complete AttributeStatement.
    stmt_template = string.Template(ATTRIBUTE_STATEMENT)
    statement = stmt_template.substitute(params)
    params['ATTRIBUTE_STATEMENT'] = statement

def _get_in_response_to(params):
    """
    Insert InResponseTo if we have a RequestID.
    Modifies the params dict.
    """
    #NOTE: I don't like this. We're mixing templating logic here, but the
    # current design requires this; maybe refactor using better templates, or
    # just bite the bullet and use elementtree to produce the XML; see comments
    # in xml_templates about Canonical XML.
    request_id = params.get('REQUEST_ID', None)
    if request_id:
        params['IN_RESPONSE_TO'] = 'InResponseTo="%s" ' % request_id
    else:
        params['IN_RESPONSE_TO'] = ''

def _get_subject(params):
    """
    Insert Subject.
    Modifies the params dict.
    """
    template = string.Template(SUBJECT)
    params['SUBJECT_STATEMENT'] = template.substitute(params)

def _get_assertion_xml(template, parameters, signed=False):
    # Reset signature.
    params = {}
    params.update(parameters)
    params['ASSERTION_SIGNATURE'] = ''
    template = string.Template(template)

    _get_in_response_to(params)
    _get_subject(params) # must come before _get_attribute_statement()
    _get_attribute_statement(params)

    unsigned = template.substitute(params)
    logging.debug('Unsigned:')
    logging.debug(unsigned)
    if not signed:
        return unsigned

    # Sign it.
    signature_xml = get_signature_xml(unsigned, params['ASSERTION_ID'])
    params['ASSERTION_SIGNATURE'] = signature_xml
    signed = template.substitute(params)

    logging.debug('Signed:')
    logging.debug(signed)
    return signed

def get_assertion_googleapps_xml(parameters, signed=False):
    return _get_assertion_xml(ASSERTION_GOOGLE_APPS, parameters, signed)

def get_assertion_salesforce_xml(parameters, signed=False):
    return _get_assertion_xml(ASSERTION_SALESFORCE, parameters, signed)

def get_response_xml(parameters, signed=False):
    """
    Returns XML for response, with signatures, if signed is True.
    """
    # Reset signatures.
    params = {}
    params.update(parameters)
    params['RESPONSE_SIGNATURE'] = ''
    _get_in_response_to(params)

    template = string.Template(RESPONSE)
    unsigned = template.substitute(params)

    logging.debug('Unsigned:')
    logging.debug(unsigned)
    if not signed:
        return unsigned

    # Sign it.
    signature_xml = get_signature_xml(unsigned, params['RESPONSE_ID'])
    params['RESPONSE_SIGNATURE'] = signature_xml
    signed = template.substitute(params)

    logging.debug('Signed:')
    logging.debug(signed)
    return signed
