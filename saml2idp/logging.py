# -*- coding: utf-8 -*-
import structlog


def get_saml_logger():
    """
    Get a logger named `saml2idp` after the main package.
    """
    return structlog.get_logger('saml2idp')
