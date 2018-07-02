"""
Signing code goes here.
"""
import base64
import hashlib
import logging

import OpenSSL.crypto

from . import types as TS
from . import xml_templates
from .utils import certificate_to_string

logger = logging.getLogger(__name__)


def sign_with_rsa(private_key: TS.PKey, data: str):
    """Sign some data, and return the base64 encoded string."""
    data = OpenSSL.crypto.sign(private_key, data, "sha1")
    return base64.b64encode(data).decode('ascii')


def get_signature_xml(
    certificate: TS.X509,
    private_key: TS.PKey,
    subject: str,
    reference_uri: str,
) -> TS.XmlNode:
    """
    Returns XML Signature for subject.
    """
    logger.debug('get_signature_xml - Begin.')
    logger.debug('Subject: ' + subject)

    # Hash the subject.
    subject_hash = hashlib.sha1()
    subject_hash.update(subject.encode('utf-8'))
    subject_digest = base64.b64encode(subject_hash.digest()).decode('utf-8')
    logger.debug('Subject digest: {}'.format(subject_digest))

    # Create signed_info.
    signed_info = xml_templates.SignedInfoTemplate({
        'REFERENCE_URI': reference_uri,
        'SUBJECT_DIGEST': subject_digest,
    })
    logger.debug('SignedInfo XML: ' + signed_info.get_xml_string())

    rsa_signature = sign_with_rsa(private_key, signed_info.get_xml_string())
    logger.debug('RSA Signature: {}'.format(rsa_signature))

    # Put the signed_info and rsa_signature into the XML signature.

    signature_xml = xml_templates.SignatureTemplate({
        'RSA_SIGNATURE': rsa_signature,
        'SIGNED_INFO': signed_info.xml,
        'CERTIFICATE': certificate_to_string(certificate),
    })

    logger.info('Signature XML: ' + signature_xml.get_xml_string())
    return signature_xml.xml
