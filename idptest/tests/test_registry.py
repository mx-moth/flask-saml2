# -*- coding: utf-8 -*-
from __future__ import unicode_literals, absolute_import
from mock import patch

from saml2idp import registry
from saml2idp import saml2idp_metadata
from saml2idp.base import Processor


class OldStyleProcessor(Processor):

    def __init__(self, config):
        super(OldStyleProcessor, self).__init__(config)


class NewStyleProcessor(Processor):
    pass



def test_getting_old_style_processor():
    sp_name = 'old_style'
    sp_config = {'processor': 'tests.test_registry.OldStyleProcessor',
                 'acs_url': 'http://somwhere.com'}

    with patch('warnings.warn') as warn:
        instance = registry.get_processor(sp_name, sp_config)
        assert instance.name == sp_name
        assert instance._config == sp_config
        assert warn.call_count == 1


def test_getting_new_style_processor():
    sp_name = 'new_style'
    sp_config = {'processor': 'tests.test_registry.NewStyleProcessor',
                 'acs_url': 'http://somwhere.com'}

    with patch('warnings.warn') as warn:
        instance = registry.get_processor(sp_name, sp_config)
        assert instance.name == sp_name
        assert instance._config == sp_config
        assert warn.call_count == 0
