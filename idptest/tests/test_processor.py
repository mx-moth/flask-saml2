# -*- coding: utf-8 -*-
from __future__ import absolute_import
import pytest

from django.core.exceptions import ImproperlyConfigured

from saml2idp import base


def test_initialising_processor_with_wrong_config():
    with pytest.raises(ImproperlyConfigured):
        base.Processor({'invalid': 'config'})

    with pytest.raises(ImproperlyConfigured):
        base.Processor({'acs_url': 'https://somewhere.io/saml/acs',
                        'processor': 'some.package.SamlProcessor'})

    with pytest.raises(ImproperlyConfigured):
        base.Processor({'processor': 'saml2idp.base.Processor'})


def test_initialising_processor_correct_config():
    config = {'acs_url': 'https://somewhere.io/saml/acs',
              'processor': 'saml2idp.base.Processor'}
    processor = base.Processor(config)

    assert sorted(processor._config.items()) == sorted(config.items())
