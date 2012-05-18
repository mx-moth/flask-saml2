"""
Signing code goes here.
"""
# python:
import hashlib
import logging
import string
# other libraries:
import M2Crypto
# this app:
import saml2idp_settings
from codex import nice64
from xml_templates import SIGNED_INFO, SIGNATURE

def load_cert_data(certificate_file):
    """
    Returns the certificate data out of the certificate_file.
    """
    certificate = M2Crypto.X509.load_cert(certificate_file)
    cert_data = ''.join(certificate.as_pem().split('\n')[1:-2])
    return cert_data

def get_signature_xml(subject, reference_uri):
    """
    Returns XML Signature for subject.
    """
    private_key_file = saml2idp_settings.SAML2IDP_PRIVATE_KEY_FILE
    certificate_file = saml2idp_settings.SAML2IDP_CERTIFICATE_FILE
    logging.debug('get_signature_xml - Begin.')
    logging.debug('Using private key file: ' + private_key_file)
    logging.debug('Using certificate file: ' + certificate_file)
    logging.debug('Subject: ' + subject)

    # Hash the subject.
    subject_hash = hashlib.sha1()
    subject_hash.update(subject)
    subject_digest = nice64(subject_hash.digest())
    logging.debug('Subject digest: ' + subject_digest)

    # Create signed_info.
    signed_info = string.Template(SIGNED_INFO).substitute({
        'REFERENCE_URI': reference_uri,
        'SUBJECT_DIGEST': subject_digest,
        })
    logging.debug('SignedInfo XML: ' + signed_info)

#    # "Digest" the signed_info.
#    info_hash = hashlib.sha1()
#    info_hash.update(signed_info)
#    info_digest = info_hash.digest()
#    logging.debug('Info digest: ' + nice64(info_digest))

    # RSA-sign the signed_info.
    private_key = M2Crypto.EVP.load_key(private_key_file)
    private_key.sign_init()
    private_key.sign_update(signed_info)
    rsa_signature = nice64(private_key.sign_final())
    logging.debug('RSA Signature: ' + rsa_signature)

    # Load the certificate.
    cert_data = load_cert_data(certificate_file)

    # Put the signed_info and rsa_signature into the XML signature.
    signed_info_short = signed_info.replace(' xmlns:ds="http://www.w3.org/2000/09/xmldsig#"', '')
    signature_xml = string.Template(SIGNATURE).substitute({
        'RSA_SIGNATURE': rsa_signature,
        'SIGNED_INFO': signed_info_short,
        'CERTIFICATE': cert_data,
        })
    logging.debug('Signature XML: ' + signature_xml)
    return signature_xml
