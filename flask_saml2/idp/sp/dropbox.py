import datetime

import pytz

from flask_saml2.idp import SPHandler
from flask_saml2.signing import Sha256Digester


class DropboxSPHandler(SPHandler):
    """
    Dropbox :class:`SPHandler` implementation.
    """

    def get_sp_digester(self):
        return Sha256Digester()

    def format_datetime(self, value: datetime.datetime) -> str:
        """
        Dropbox does not like too much precision in its seconds, and only
        supports UTC as Z, not an hourly offset.
        """
        return value.astimezone(pytz.utc).strftime('%Y-%m-%dT%H:%M:%SZ')
