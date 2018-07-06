"""
Signing code goes here.
"""
import base64
import hashlib
import logging
from typing import ClassVar, Sequence, Tuple, Union
from urllib.parse import urlencode

import OpenSSL.crypto

from flask_saml2.types import X509, PKey, XmlNode

from . import xml_templates
from .utils import certificate_to_string

logger = logging.getLogger(__name__)


class Digester:
    """All the digest methods supported."""
    uri: ClassVar[str]

    def __call__(self, data):
        return base64.b64encode(self.make_digest(data)).decode('utf-8')

    def make_digest(self, data):
        raise NotImplementedError


class Sha1Digester(Digester):
    uri = 'http://www.w3.org/2000/09/xmldsig#sha1'

    def make_digest(self, data):
        return hashlib.sha1(data).digest()


class Signer:
    """
    Sign some data with a particular algorithm. Each Signer may take different
    constructor arguments, but each will have a uri attribute and will sign
    data when called.
    """
    uri: ClassVar[str]

    def __call__(self, data):
        raise NotImplementedError


class RsaSha1Signer(Signer):
    uri = 'http://www.w3.org/2000/09/xmldsig#rsa-sha1'

    def __init__(self, key: Union[X509, PKey]):
        self.key = key

    def __call__(self, data: bytes):
        data = OpenSSL.crypto.sign(self.key, data, "sha1")
        return base64.b64encode(data).decode('ascii')


def sign_with_certificate(certificate: X509, data: str, digest: str = 'sha1'):
    """Sign some data, and return the base64 encoded string."""
    data = OpenSSL.crypto.sign(certificate, data, digest)
    return base64.b64encode(data).decode('ascii')


def get_signature_xml(
    certificate: X509,
    digester: Digester,
    signer: Signer,
    subject: str,
    reference_uri: str,
) -> XmlNode:
    """
    Returns XML Signature for subject.
    """
    logger.debug('get_signature_xml - Begin.')
    logger.debug('Subject: ' + subject)

    # Hash the subject.
    subject_digest = digester(subject.encode('utf-8'))
    logger.debug('Subject digest: {}'.format(subject_digest))

    # Create signed_info.
    signed_info = xml_templates.SignedInfoTemplate({
        'REFERENCE_URI': reference_uri,
        'SUBJECT_DIGEST': subject_digest,
        'DIGESTER': digester,
        'SIGNER': signer,
    })

    signature = signer(signed_info.get_xml_string().encode('utf-8'))
    logger.debug('Signature: {}'.format(signature))

    # Put the signed_info and rsa_signature into the XML signature.

    signature_xml = xml_templates.SignatureTemplate({
        'SIGNATURE': signature,
        'SIGNED_INFO': signed_info.xml,
        'CERTIFICATE': certificate_to_string(certificate),
    })

    return signature_xml.xml


def sign_query_parameters(
    signer: Signer,
    bits: Sequence[Tuple[str, str]],
) -> str:
    """
    Sign the bits of a query string.

    .. code-block:: python

        >>> signer = ...  # A Signer instance
        >>> bits = [('Foo', '1'), ('Bar', '2')]
        >>> sign_query_parameters(signer, bits)
        "Foo=1&Bar=2&SigAlg=...&Signature=..."
    """
    bits = list(bits)

    # Add the signature algorithm parameter
    bits.append(('SigAlg', signer.uri))

    # Sign the encoded query string
    data = urlencode(bits, encoding='utf-8').encode('utf-8')
    bits.append(('Signature', signer(data)))

    return urlencode(bits, encoding='utf-8')
