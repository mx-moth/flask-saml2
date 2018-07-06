"""
Functions for creating XML output.
"""
import logging
from typing import Optional, Type

from flask_saml2.signing import Digester, Signer, get_signature_xml
from flask_saml2.types import X509

from .xml_templates import ResponseTemplate, XmlTemplate

logger = logging.getLogger(__name__)


def _get_in_response_to(params):
    """Insert InResponseTo if we have a RequestID."""
    request_id = params.get('REQUEST_ID', None)
    if request_id:
        return {
            'IN_RESPONSE_TO': request_id,
            **params,
        }
    else:
        return params


def get_assertion_xml(
    template_klass: Type[XmlTemplate],
    parameters: dict,
    *,
    digester: Optional[Digester] = None,
    signer: Optional[Signer] = None,
    certificate: Optional[X509] = None,
) -> XmlTemplate:
    params = _get_in_response_to(parameters)

    assertion = template_klass(params)
    if signer is None:
        return assertion

    # Sign it.
    assertion.add_signature(get_signature_xml(
        certificate, digester, signer,
        assertion.get_xml_string(), params['ASSERTION_ID']))

    return assertion


def get_response_xml(
    parameters: dict,
    assertion: XmlTemplate,
    *,
    digester: Optional[Digester] = None,
    signer: Optional[Signer] = None,
    certificate: Optional[X509] = None,
) -> XmlTemplate:
    """Returns XML for response, with signatures if a signer is supplied."""
    params = _get_in_response_to(parameters)

    response = ResponseTemplate(params, assertion.xml)

    if signer is None:
        return response

    # Sign it.
    response.add_signature(get_signature_xml(
        certificate, digester, signer,
        response.get_xml_string(), params['RESPONSE_ID']))

    return response
