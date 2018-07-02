"""
Functions for creating XML output.
"""
import logging
from typing import Optional, Type

from flask_saml2.types import X509, PKey, XmlNode
from flask_saml2.xml_signing import get_signature_xml

from .xml_templates import ResponseTemplate, XmlTemplate

logger = logging.getLogger(__name__)


def _get_in_response_to(params):
    """
    Insert InResponseTo if we have a RequestID.
    Modifies the params dict.
    """
    request_id = params.get('REQUEST_ID', None)
    if request_id:
        params['IN_RESPONSE_TO'] = request_id


def get_assertion_xml(
    template_klass: Type[XmlTemplate],
    parameters: dict,
    *,
    signed: bool = False,
    certificate: Optional[X509] = None,
    private_key: Optional[PKey] = None,
) -> XmlNode:
    # Reset signature.
    params = {**parameters}
    _get_in_response_to(params)

    assertion = template_klass(params)
    logger.debug('Unsigned:')
    logger.debug(assertion.get_xml_string())
    if not signed:
        return assertion.xml

    # Sign it.
    assertion.add_signature(get_signature_xml(
        certificate, private_key,
        assertion.get_xml_string(), params['ASSERTION_ID']))

    logger.debug('Signed:')
    logger.debug(assertion.get_xml_string())
    return assertion.xml


def get_response_xml(
    parameters: dict,
    assertion: XmlNode,
    *,
    signed: bool = False,
    certificate: Optional[X509] = None,
    private_key: Optional[PKey] = None,
) -> str:
    """
    Returns XML for response, with signatures, if signed is True.
    """
    # Reset signatures.
    params = {
        **parameters,
        'RESPONSE_SIGNATURE': '',
    }
    _get_in_response_to(params)

    response = ResponseTemplate(params, assertion)

    logger.debug('Unsigned:')
    logger.debug(response.get_xml_string())
    if not signed:
        return response.get_xml_string()

    # Sign it.
    response.add_signature(get_signature_xml(
        certificate, private_key,
        response.get_xml_string(), params['RESPONSE_ID']))

    logger.debug('Signed:')
    logger.debug(response.get_xml_string())
    return response.get_xml_string()
