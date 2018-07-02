import datetime
import typing as T
import uuid
from importlib import import_module

import OpenSSL.crypto

from . import types as TS


def import_string(path: str) -> T.Any:
    """
    Import a dotted Python path to a class or other module attribute.
    ``import_string('foo.bar.MyClass')`` will return the class ``MyClass`` from
    the package ``foo.bar``.
    """
    name, attr = path.rsplit('.', 1)
    return getattr(import_module(name), attr)


def get_random_id() -> str:
    """
    Generate a random ID string. The random ID will start with the '_'
    character.
    """
    # It is very important that these random IDs NOT start with a number.
    random_id = '_' + uuid.uuid4().hex
    return random_id


def get_time_string(**kwargs) -> str:
    """
    Make an ISO 8601 UTC datetime string for a datetime, offset from now
    according to kwargs. See :class:`datetime.timedelta` for possible kwargs.
    """
    delta = datetime.timedelta(**kwargs)
    datestamp = datetime.datetime.utcnow() - delta
    return datestamp.isoformat()


def certificate_to_string(certificate: TS.X509) -> str:
    """
    Take an x509 certificate and encode it to a string suitable for adding to
    XML responses.
    """
    pem_bytes = OpenSSL.crypto.dump_certificate(
        OpenSSL.crypto.FILETYPE_PEM, certificate)
    return ''.join(pem_bytes.decode('ascii').strip().split('\n')[1:-1])


def certificate_from_string(
    certificate: str,
    format=OpenSSL.crypto.FILETYPE_PEM,
) -> TS.X509:
    """
    Load an X509 certificate from a string. This just strips off the header and
    footer text.
    """
    return OpenSSL.crypto.load_certificate(format, certificate)


def certificate_from_file(
    filename: str,
    format=OpenSSL.crypto.FILETYPE_PEM,
) -> TS.X509:
    """Load an X509 certificate from ``filename``."""
    with open(filename, 'r') as handle:
        return certificate_from_string(handle.read(), format)


def private_key_from_string(
    private_key: str,
    format=OpenSSL.crypto.FILETYPE_PEM,
) -> TS.PKey:
    """Load a private key from a string."""
    return OpenSSL.crypto.load_privatekey(format, private_key)


def private_key_from_file(
    filename: str,
    format=OpenSSL.crypto.FILETYPE_PEM,
) -> TS.PKey:
    """Load a private key from ``filename``."""
    with open(filename, 'r') as handle:
        return private_key_from_string(handle.read(), format)
