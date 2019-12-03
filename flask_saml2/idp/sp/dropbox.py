import datetime

import pytz

from flask_saml2.idp import SPHandler
from flask_saml2.signing import RsaSha256Signer, Sha256Digester


class DropboxSPHandler(SPHandler):
    """
    Dropbox :class:`SPHandler` implementation.
    """
    require_destination = False

    def get_sp_digester(self):
        return Sha256Digester()

    def get_sp_signer(self):
        private_key = self.idp.get_idp_private_key()
        return RsaSha256Signer(private_key)

    def format_datetime(self, value: datetime.datetime) -> str:
        """
        Dropbox does not like too much precision in its seconds, and only
        supports UTC as Z, not an hourly offset.
        """
        return value.astimezone(pytz.utc).strftime('%Y-%m-%dT%H:%M:%SZ')
