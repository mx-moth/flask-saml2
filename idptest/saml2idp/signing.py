"""
Signing code goes here.
"""
import hashlib
import M2Crypto
import base64
import saml2idp_settings

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
        certificate = f.read()
        f.close()
        return certificate

    def get_signature(self, unsigned_subject):
        """
        Returns signature (digest, value, certificate) tuple, all base64-encoded.
        """
        hash = hashlib.sha1()
        hash.update(unsigned_subject)
        digest = base64.b64encode(hash.digest())

        private_key = self.get_private_key()
        m = M2Crypto.RSA.load_key_string(private_key)
        signature = m.sign(hash.digest(),"sha1")
        value = base64.b64encode(signature)

        certificate = self.get_certificate()
        cert = base64.b64encode(certificate)

        return (digest, value, cert)
