"""
https://github.com/XML-Security/signxml/blob/master/LICENSE

   Copyright 2014 Andrey Kislyuk

   Licensed under the Apache License, Version 2.0 (the "License");
   you may not use this file except in compliance with the License.
   You may obtain a copy of the License at

       http://www.apache.org/licenses/LICENSE-2.0

   Unless required by applicable law or agreed to in writing, software
   distributed under the License is distributed on an "AS IS" BASIS,
   WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
   See the License for the specific language governing permissions and
   limitations under the License.
"""
import M2Crypto
import hashlib
from base64 import b64decode
from lxml import etree
from signxml import XMLVerifier, VerifyResult,\
    ds_tag, fromstring, InvalidInput, InvalidDigest, InvalidSignature, namespaces


class M2XMLVerifier(XMLVerifier):
    """
    Uses M2Crypto instead of pyOpenSSL

    Allows us to ignore certificate signing as self signed certificates
    are fine to use provided you prefetch the SPs certificate from
    their metadata AND do so over a secure connection.
    """

    def verify(self, data, require_x509=True, x509_cert=None, cert_subject_name=None, ca_pem_file=None, ca_path=None,
               hmac_key=None, validate_schema=True, parser=None, uri_resolver=None, id_attribute=None,
               expect_references=1):
        """
        See XMLVerifier.verify
        """
        # Using args, kwargs makes it easier to call super
        # ...sort of
        args = [data]
        kwargs = {
            'require_x509': require_x509,
            'x509_cert': x509_cert,
            'cert_subject_name': cert_subject_name,
            'ca_pem_file': ca_pem_file,
            'ca_path': ca_path,
            'hmac_key': hmac_key,
            'validate_schema': validate_schema,
            'parser': parser,
            'uri_resolver': uri_resolver,
            'id_attribute': id_attribute,
            'expect_references': expect_references,
        }
        self.hmac_key = hmac_key
        self.require_x509 = require_x509
        self.x509_cert = x509_cert
        self._parser = parser

        if self.x509_cert:
            self.require_x509 = True

        if id_attribute is not None:
            self.id_attributes = (id_attribute, )

        root = self.get_root(data)
        if root.tag == ds_tag("Signature"):
            signature_ref = root
        else:
            signature_ref = self._find(root, "Signature", anywhere=True)

        # HACK: deep copy won't keep root's namespaces
        signature = fromstring(etree.tostring(signature_ref), parser=parser)

        if validate_schema:
            self.schema().assertValid(signature)

        signed_info = self._find(signature, "SignedInfo")
        c14n_method = self._find(signed_info, "CanonicalizationMethod")
        c14n_algorithm = c14n_method.get("Algorithm")
        signature_method = self._find(signed_info, "SignatureMethod")
        signature_value = self._find(signature, "SignatureValue")
        signature_alg = signature_method.get("Algorithm")
        raw_signature = b64decode(signature_value.text)
        x509_data = signature.find("ds:KeyInfo/ds:X509Data", namespaces=namespaces)
        signed_info_c14n = self._c14n(signed_info, algorithm=c14n_algorithm)

        if x509_data is not None or self.require_x509:
            if self.x509_cert is None:
                if x509_data is None:
                    raise InvalidInput("Expected a X.509 certificate based signature")
                certs = [cert.text for cert in self._findall(x509_data, "X509Certificate")]
                if not certs:
                    msg = "Expected to find an X509Certificate element in the signature"
                    msg += " (X509SubjectName, X509SKI are not supported)"
                    raise InvalidInput(msg)

                elif len(certs) > 1:
                    msg = "Currently cannot handle more than 1 certificate."
                    raise InvalidInput(msg)

                signing_cert = certs[0]  # TODO: handle chains
            else:
                signing_cert = self.x509_cert

            signature_digest_method = self._get_signature_digest_method(signature_alg).name
            try:
                x509_cert_str = '-----BEGIN CERTIFICATE-----\n' + signing_cert + '\n-----END CERTIFICATE-----'
                x509_cert = M2Crypto.X509.load_cert_string(x509_cert_str.encode('utf-8'))

                # Digest SignedInfo
                signed_info_hash = hashlib.new(signature_digest_method)
                signed_info_hash.update(signed_info_c14n)
                signed_info_digest = signed_info_hash.digest()

                pub_key = x509_cert.get_pubkey()
                pub_key.reset_context(md=signature_digest_method)
                pub_key.verify_init()
                assert pub_key.verify_update(signed_info_digest) == 1, 'verify_update failed'
                result = pub_key.verify_final(raw_signature)
                assert result != -1, 'Error in verify_final'
            except AssertionError:
                raise InvalidSignature("Signature verification failed")
        elif "hmac-sha" in signature_alg:
            return super(M2XMLVerifier, self).verify(*args, **kwargs)
        else:
            key_value = signature.find("ds:KeyInfo/ds:KeyValue", namespaces=namespaces)
            if key_value is None:
                raise InvalidInput("Expected to find either KeyValue or X509Data XML element in KeyInfo")

            self._verify_signature_with_pubkey(signed_info_c14n, raw_signature, key_value, signature_alg)

        verify_results = []
        for reference in self._findall(signed_info, "Reference"):
            transforms = self._find(reference, "Transforms", require=False)
            digest_algorithm = self._find(reference, "DigestMethod").get("Algorithm")
            digest_value = self._find(reference, "DigestValue")
            payload = self._resolve_reference(root, reference, uri_resolver=uri_resolver)
            payload_c14n = self._apply_transforms(payload, transforms, signature_ref, c14n_algorithm)
            if digest_value.text != self._get_digest(payload_c14n, self._get_digest_method(digest_algorithm)):
                raise InvalidDigest("Digest mismatch for reference {}".format(len(verify_results)))

            # We return the signed XML (and only that) to ensure no access to unsigned data happens
            try:
                payload_c14n_xml = fromstring(payload_c14n)
            except etree.XMLSyntaxError:
                payload_c14n_xml = None
            verify_results.append(VerifyResult(payload_c14n, payload_c14n_xml, signature))

        if type(expect_references) is int and len(verify_results) != expect_references:
            msg = "Expected to find {} references, but found {}"
            raise InvalidSignature(msg.format(expect_references, len(verify_results)))

        return verify_results if expect_references > 1 else verify_results[0]
