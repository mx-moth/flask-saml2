# -*- coding: utf-8 -*-
from __future__ import unicode_literals, absolute_import
import pytest

from django.core.exceptions import ImproperlyConfigured

from saml2idp import saml2idp_metadata as smd


@pytest.mark.parametrize('config', [
    {'key-i-dont': 'care-about'},
    {smd.CERTIFICATE_DATA: 'some data',
     smd.CERTIFICATE_FILENAME: 'filename'}])
def test_checking_configuration_fails_on_invalid_configs(config):
    with pytest.raises(ImproperlyConfigured):
        smd.check_configuration_contains(config, [smd.CERTIFICATE_DATA,
                                                  smd.CERTIFICATE_FILENAME])


@pytest.mark.parametrize('config', [
    {smd.CERTIFICATE_DATA: 'some data'},
    {smd.CERTIFICATE_FILENAME: 'filename'}])
def test_configuration_is_validated_correctly(config):
    smd.check_configuration_contains(config, [smd.CERTIFICATE_DATA,
                                              smd.CERTIFICATE_FILENAME])
