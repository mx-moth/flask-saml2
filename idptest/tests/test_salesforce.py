"""
Tests for the SalesForce processor.
"""
# standard library imports:
import base64
# local imports:
import base

SAML_REQUEST = base64.b64encode(
    '<?xml version="1.0" encoding="UTF-8"?>'
    '<samlp:AuthnRequest '
    'AssertionConsumerServiceURL="https://login.salesforce.com" '
    'Destination="http://127.0.0.1:8000/+saml" '
    'ID="_23_w1uySFqdqmNiZz17aYPnxrtIgaREEtADQVlNz4KrWC4aSYvJcwfdqKOg7K_WDhRQN4u.r.L8T6.uF_.jedrRE9erwC8pQW3DU3QqWHHMkgcQM.YaRfs.k2fRuxJy1LWTpkBKclS7wEetDew124SVn9IXC1S101qA1UPzOnym4WISbxLqIN9zJUNoafpSEkmm3cVrrALn1d5fvpbxWnFACsOVfCrA" '
    'IssueInstant="2011-10-05T18:49:49.068Z" '
    'ProtocolBinding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST" '
    'Version="2.0" xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol">'
    '<saml:Issuer xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion">'
    'https://saml.salesforce.com</saml:Issuer>'
    '<ds:Signature xmlns:ds="http://www.w3.org/2000/09/xmldsig#">'
    '<ds:SignedInfo xmlns:ds="http://www.w3.org/2000/09/xmldsig#">'
    '<ds:CanonicalizationMethod '
    'Algorithm="http://www.w3.org/2001/10/xml-exc-c14n#" '
    'xmlns:ds="http://www.w3.org/2000/09/xmldsig#"/>'
    '<ds:SignatureMethod Algorithm="http://www.w3.org/2000/09/xmldsig#rsa-sha1" '
    'xmlns:ds="http://www.w3.org/2000/09/xmldsig#"/>'
    '<ds:Reference URI="#_23_w1uySFqdqmNiZz17aYPnxrtIgaREEtADQVlNz4KrWC4aSYvJcwfdqKOg7K_WDhRQN4u.r.L8T6.uF_.jedrRE9erwC8pQW3DU3QqWHHMkgcQM.YaRfs.k2fRuxJy1LWTpkBKclS7wEetDew124SVn9IXC1S101qA1UPzOnym4WISbxLqIN9zJUNoafpSEkmm3cVrrALn1d5fvpbxWnFACsOVfCrA" '
    'xmlns:ds="http://www.w3.org/2000/09/xmldsig#">'
    '<ds:Transforms xmlns:ds="http://www.w3.org/2000/09/xmldsig#">'
    '<ds:Transform Algorithm="http://www.w3.org/2000/09/xmldsig#enveloped-signature" '
    'xmlns:ds="http://www.w3.org/2000/09/xmldsig#"/>'
    '<ds:Transform Algorithm="http://www.w3.org/2001/10/xml-exc-c14n#" '
    'xmlns:ds="http://www.w3.org/2000/09/xmldsig#">'
    '<ec:InclusiveNamespaces PrefixList="ds saml samlp" '
    'xmlns:ec="http://www.w3.org/2001/10/xml-exc-c14n#"/></ds:Transform>'
    '</ds:Transforms>'
    '<ds:DigestMethod Algorithm="http://www.w3.org/2000/09/xmldsig#sha1" '
    'xmlns:ds="http://www.w3.org/2000/09/xmldsig#"/>'
    '<ds:DigestValue xmlns:ds="http://www.w3.org/2000/09/xmldsig#">'
    'U/a7bDdeu3+i+Eh/K72AVo66G3c=</ds:DigestValue></ds:Reference>'
    '</ds:SignedInfo><ds:SignatureValue '
    'xmlns:ds="http://www.w3.org/2000/09/xmldsig#">'
    'rExn4AG/W4/cu3/CGbUAdhFua7yQoJmGnLeaH0QaQpUphLsulG9jpRBuS7Zuyqy4UtEd9j4B1syo'
    't9A7azz+3+eYeg/86OiQ2rZjlphjsbQIocvVlUd40taSH13gMQ9gMsuYy01WjkcM2vlXA9cHK8Ge'
    'F/6hgRQGpVSzrXMO0ro=</ds:SignatureValue><ds:KeyInfo><ds:X509Data>'
    '<ds:X509Certificate>'
    'MIIEijCCA/OgAwIBAgIQPn+ClEjH2V3Jynt7u3v+XzANBgkqhkiG9w0BAQUFADCBujEfMB0GA1UE'
    'ChMWVmVyaVNpZ24gVHJ1c3QgTmV0d29yazEXMBUGA1UECxMOVmVyaVNpZ24sIEluYy4xMzAxBgNV'
    'BAsTKlZlcmlTaWduIEludGVybmF0aW9uYWwgU2VydmVyIENBIC0gQ2xhc3MgMzFJMEcGA1UECxNA'
    'd3d3LnZlcmlzaWduLmNvbS9DUFMgSW5jb3JwLmJ5IFJlZi4gTElBQklMSVRZIExURC4oYyk5NyBW'
    'ZXJpU2lnbjAeFw0xMDEyMTQwMDAwMDBaFw0xMjAxMDcyMzU5NTlaMIGOMQswCQYDVQQGEwJVUzET'
    'MBEGA1UECBMKQ2FsaWZvcm5pYTEWMBQGA1UEBxQNU2FuIEZyYW5jaXNjbzEdMBsGA1UEChQUU2Fs'
    'ZXNmb3JjZS5jb20sIEluYy4xFDASBgNVBAsUC0FwcGxpY2F0aW9uMR0wGwYDVQQDFBRwcm94eS5z'
    'YWxlc2ZvcmNlLmNvbTCBnzANBgkqhkiG9w0BAQEFAAOBjQAwgYkCgYEAzKElluHQYlUnFm156Nwu'
    'p9vqkf9DvnhOJc09GNYKOdz5PkpJ/bFLuN2frmfJTlw6pi4knE2geN3j26iAFGIpqgkfWmAi5knj'
    'cIbOvHbMXMg1apuVyK9jmbKy4pITZCj56PtH7qMjlmwN+ZEcQRVy+urRGJRfBEyE+ht5KrewhlcC'
    'AwEAAaOCAbkwggG1MAkGA1UdEwQCMAAwCwYDVR0PBAQDAgWgMDwGA1UdHwQ1MDMwMaAvoC2GK2h0'
    'dHA6Ly9TVlJJbnRsLWNybC52ZXJpc2lnbi5jb20vU1ZSSW50bC5jcmwwRAYDVR0gBD0wOzA5Bgtg'
    'hkgBhvhFAQcXAzAqMCgGCCsGAQUFBwIBFhxodHRwczovL3d3dy52ZXJpc2lnbi5jb20vcnBhMDQG'
    'A1UdJQQtMCsGCWCGSAGG+EIEAQYKKwYBBAGCNwoDAwYIKwYBBQUHAwEGCCsGAQUFBwMCMHEGCCsG'
    'AQUFBwEBBGUwYzAkBggrBgEFBQcwAYYYaHR0cDovL29jc3AudmVyaXNpZ24uY29tMDsGCCsGAQUF'
    'BzAChi9odHRwOi8vU1ZSSW50bC1haWEudmVyaXNpZ24uY29tL1NWUkludGwtYWlhLmNlcjBuBggr'
    'BgEFBQcBDARiMGChXqBcMFowWDBWFglpbWFnZS9naWYwITAfMAcGBSsOAwIaBBRLa7kolgYMu9BS'
    'OJsprEsHiyEFGDAmFiRodHRwOi8vbG9nby52ZXJpc2lnbi5jb20vdnNsb2dvMS5naWYwDQYJKoZI'
    'hvcNAQEFBQADgYEAHP9jTz8c1r9YoOhVxbGwdPx/YU4OaEaiJFqRKrdXu4m6tHp2iW7o/7Kc8Ixk'
    'sDB4siloTOcJ25/NsfPRoWDyvwax0aXDzsBRwJ5Qpr+ii3bUI1+QByEdxH4gZVHHu9fMG/+ePr9S'
    'Hhil20oycE7oe0xvQEad1Hs6xHCRDbJVIr4=</ds:X509Certificate></ds:X509Data>'
    '</ds:KeyInfo></ds:Signature></samlp:AuthnRequest>'
    )
RELAY_STATE = '/home/home.jsp'
REQUEST_DATA = {
    'SAMLRequest': SAML_REQUEST,
    'RelayState': RELAY_STATE,
}
SALESFORCE_ACS = 'https://login.salesforce.com'


class TestSalesForceProcessor(base.TestBaseProcessor):
    SP_CONFIG = {
        'acs_url': SALESFORCE_ACS,
        'processor': 'saml2idp.salesforce.Processor',
    }
    REQUEST_DATA = REQUEST_DATA
