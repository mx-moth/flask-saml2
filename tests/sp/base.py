from pathlib import Path

from flask_saml2.utils import certificate_from_file, private_key_from_file

KEY_DIR = Path(__file__).parent.parent / 'keys' / 'sample'
CERTIFICATE_FILE = KEY_DIR / 'idp-certificate.pem'
PRIVATE_KEY_FILE = KEY_DIR / 'idp-private-key.pem'

CERTIFICATE = certificate_from_file(CERTIFICATE_FILE)
PRIVATE_KEY = private_key_from_file(PRIVATE_KEY_FILE)
