# -*- coding: utf-8 -*-
"""
Functions for creating XML output.
"""
from __future__ import absolute_import
import logging

from . import xml_templates
from .xml_signing import get_signature_xml

logger = logging.getLogger(__name__)


def _get_in_response_to(params):
    """
    Insert InResponseTo if we have a RequestID.
    Modifies the params dict.
    """
    request_id = params.get('REQUEST_ID', None)
    if request_id:
        params['IN_RESPONSE_TO'] = request_id


def _get_assertion_xml(template_klass, parameters, signed=False):
    # Reset signature.
    params = {}
    params.update(parameters)

    _get_in_response_to(params)

    assertion = template_klass(params)
    logger.debug('Unsigned:')
    logger.debug(assertion.get_xml_string())
    if not signed:
        return assertion.xml

    # Sign it.
    assertion.add_signature(get_signature_xml(assertion.get_xml_string(), params['ASSERTION_ID']))

    logger.debug('Signed:')
    logger.debug(assertion.get_xml_string())
    return assertion.xml


def get_assertion_googleapps_xml(parameters, signed=False):
    return _get_assertion_xml(xml_templates.AssertionGoogleAppsTemplate, parameters, signed)


def get_assertion_salesforce_xml(parameters, signed=False):
    return _get_assertion_xml(xml_templates.AssertionSalesforceTemplate, parameters, signed)


def get_response_xml(parameters, assertion, signed=False):
    """
    Returns XML for response, with signatures, if signed is True.
    """
    # Reset signatures.
    params = {}
    params.update(parameters)
    params['RESPONSE_SIGNATURE'] = ''
    _get_in_response_to(params)

    response = xml_templates.ResponseTemplate(params, assertion)

    logger.debug('Unsigned:')
    logger.debug(response.get_xml_string())
    if not signed:
        return response.get_xml_string()

    # Sign it.
    response.add_signature(get_signature_xml(response.get_xml_string(), params['RESPONSE_ID']))

    logger.debug('Signed:')
    logger.debug(response.get_xml_string())
    return response.get_xml_string()
