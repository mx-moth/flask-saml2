"""
Signing code goes here.
"""
import hashlib
import M2Crypto
import base64
from django.template import Context, Template
import saml2idp_settings
from misc import canonicalize, strip_blank_lines

class Signer(object):
    """
    Provides digital signatures, configurably. Mainly, this is for unittests.
    """
    def __init__(self, private_key_file=None, certificate_file=None):
        if private_key_file:
            self.private_key_file = private_key_file
        else:
            self.private_key_file = saml2idp_settings.SAML2IDP_PRIVATE_KEY_FILE
        if certificate_file:
            self.certificate_file = certificate_file
        else:
            self.certificate_file = saml2idp_settings.SAML2IDP_CERTIFICATE_FILE

    def get_private_key(self):
        """ Returns the private key value from the private key file. """
        f = open(self.private_key_file, "r")
        private_key = f.read()
        f.close()
        return private_key

    def get_certificate(self):
        """ Returns the certificate value from the certificate file. """
        f = open(self.certificate_file, "r")
        data = f.read()
        f.close()
        certificate = ''.join( data.split('\n')[1:-2] )
        return certificate

    def get_signature(self, ref_uri, unsigned_subject):
        """
        Returns signature (digest, value, certificate) tuple, all base64-encoded.
        Assumes unsigned_subject is already canonical XML.
        """
        hash = hashlib.sha1()
        hash.update(unsigned_subject)
        digest = base64.b64encode(hash.digest())

        private_key = self.get_private_key()
        m = M2Crypto.RSA.load_key_string(private_key)
        sha1_value = m.sign(hash.digest(),"sha1")
        value = base64.b64encode(sha1_value)

        cert = self.get_certificate()

        signature = ( {
            'reference_uri': ref_uri,
            'digest': digest,
            'value': value,
            'certificate': cert,
        } )
        return signature

    def get_assertion_signature(self, saml_request, assertion, issuer):
        """
        Returns a signature for the (unsigned) assertion.
        """
        t = Template(
            '{% load samltags %}'
            '{% assertion_xml saml_request assertion issuer %}'
        )
        c = Context({
            'saml_request': saml_request,
            'assertion': assertion,
            'issuer': issuer,
        })
        unsigned = t.render(c)
        signature = self.get_signature(assertion['id'], unsigned)
        return signature

    def get_response_signature(self, saml_request, saml_response, assertion, issuer):
        """
        Returns a signature for the entire (unsigned) response.
        """
        t = Template(
            '{% load samltags %}'
            '{% response_xml saml_request saml_response assertion issuer %}'
        )
        c = Context({
            'saml_request': saml_request,
            'saml_response': saml_response,
            'assertion': assertion,
            'issuer': issuer,
        })
        unsigned = t.render(c)
        signature = self.get_signature(saml_response['id'], unsigned)
        return signature
