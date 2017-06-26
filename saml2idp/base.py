# -*- coding: utf-8 -*-
from __future__ import absolute_import
import base64
import logging
import time
import uuid

from BeautifulSoup import BeautifulStoneSoup
from django.core.exceptions import ImproperlyConfigured

from . import codex
from . import exceptions
from . import saml2idp_metadata
from . import xml_render

MINUTES = 60
HOURS = 60 * MINUTES


def get_random_id():
    # It is very important that these random IDs NOT start with a number.
    random_id = '_' + uuid.uuid4().hex
    return random_id


def get_time_string(delta=0):
    return time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime(time.time() + delta))


# Design note: I've tried to make this easy to sub-class and override
# just the bits you need to override. I've made use of object properties,
# so that your sub-classes have access to all information: use wisely.
# Formatting note: These methods are alphabetized.
class Processor(object):
    """
    Base SAML 2.0 AuthnRequest to Response Processor.
    Sub-classes should provide Service Provider-specific functionality.
    """

    @property
    def dotted_path(self):
        return '{module}.{class_name}'.format(
            module=self.__module__,
            class_name=self.__class__.__name__)

    def __init__(self, config, name=None):
        self.name = name
        self._config = config.copy()
        self._logger = logging.getLogger(__name__)

        processor_path = self._config.get('processor', 'invalid')

        self._logger.info('initializing processor {} {}'.format(processor_path, self.dotted_path))

        if processor_path != self.dotted_path:
            raise ImproperlyConfigured(
                "config is invalid for this processor: {}".format(self._config))

        if 'acs_url' not in self._config:
            raise ImproperlyConfigured(
                "no ACS URL specified in SP configuration: {}".format(
                    self._config))

        self._logger.info('processor configured: {}'.format(str(self._config)))

    def _build_assertion(self):
        """
        Builds _assertion_params.
        """
        self._determine_assertion_id()
        self._determine_audience()
        self._determine_subject()
        self._determine_session_index()

        self._assertion_params = {
            'ASSERTION_ID': self._assertion_id,
            'ASSERTION_SIGNATURE': '', # it's unsigned
            'AUDIENCE': self._audience,
            'AUTH_INSTANT': get_time_string(),
            'ISSUE_INSTANT': get_time_string(),
            'NOT_BEFORE': get_time_string(-1 * HOURS), #TODO: Make these settings.
            'NOT_ON_OR_AFTER': get_time_string(15 * MINUTES),
            'SESSION_INDEX': self._session_index,
            'SESSION_NOT_ON_OR_AFTER': get_time_string(8 * HOURS),
            'SP_NAME_QUALIFIER': self._audience,
            'SUBJECT': self._subject,
            'SUBJECT_FORMAT': self._subject_format,
        }
        self._assertion_params.update(self._system_params)
        self._assertion_params.update(self._request_params)

    def _build_response(self):
        """
        Builds _response_params.
        """
        self._determine_response_id()
        self._response_params = {
            'ASSERTION': self._assertion_xml,
            'ISSUE_INSTANT': get_time_string(),
            'RESPONSE_ID': self._response_id,
            'RESPONSE_SIGNATURE': '',  # initially unsigned
        }
        self._response_params.update(self._system_params)
        self._response_params.update(self._request_params)

    def _decode_request(self):
        """
        Decodes _request_xml from _saml_request.
        """
        self._request_xml = base64.b64decode(self._saml_request)

        self._logger.debug('SAML request decoded: '.format(self._request_xml))

    def _determine_assertion_id(self):
        """
        Determines the _assertion_id.
        """
        self._assertion_id = get_random_id()

    def _determine_audience(self):
        """
        Determines the _audience.
        """
        self._audience = self._request_params.get('DESTINATION', None)

        if not self._audience:
            self._audience = self._request_params.get('PROVIDER_NAME', None)

        self._logger.info('determined audience: {}'.format(self._audience))

    def _determine_response_id(self):
        """
        Determines _response_id.
        """
        self._response_id = get_random_id()

    def _determine_session_index(self):
        self._session_index = self._django_request.session.session_key

    def _determine_subject(self):
        """
        Determines _subject and _subject_type for Assertion Subject.
        """
        self._subject = self._django_request.user.email

    def _encode_response(self):
        """
        Encodes _response_xml to _encoded_xml.
        """
        self._saml_response = codex.nice64(self._response_xml)

    def _extract_saml_request(self):
        """
        Retrieves the _saml_request AuthnRequest from the _django_request.
        """
        self._saml_request = self._django_request.session['SAMLRequest']
        self._relay_state = self._django_request.session['RelayState']

    def _format_assertion(self):
        """
        Formats _assertion_params as _assertion_xml.
        """
        raise NotImplemented()

    def _format_response(self):
        """
        Formats _response_params as _response_xml.
        """
        sign_it=saml2idp_metadata.SAML2IDP_CONFIG['signing']
        self._response_xml = xml_render.get_response_xml(self._response_params, signed=sign_it)

    def _get_django_response_params(self):
        """
        Returns a dictionary of parameters for the response template.
        """
        tv = {
            'acs_url': self._request_params['ACS_URL'],
            'saml_response': self._saml_response,
            'relay_state': self._relay_state,
            'autosubmit': saml2idp_metadata.SAML2IDP_CONFIG['autosubmit'],
        }
        return tv

    def _parse_request(self):
        """
        Parses various parameters from _request_xml into _request_params.
        """
        #Minimal test to verify that it's not binarily encoded still:
        if not self._request_xml.strip().startswith('<'):
            raise Exception('RequestXML is not valid XML; '
                            'it may need to be decoded or decompressed.')
        soup = BeautifulStoneSoup(self._request_xml)
        request = soup.findAll()[0]
        params = {}
        params['ACS_URL'] = request['assertionconsumerserviceurl']
        params['REQUEST_ID'] = request['id']
        params['DESTINATION'] = request.get('destination', '')
        params['PROVIDER_NAME'] = request.get('providername', '')
        self._request_params = params

    def _reset(self, django_request, sp_config=None):
        """
        Initialize (and reset) object properties, so we don't risk carrying
        over anything from the last authentication.
        If provided, use sp_config throughout; otherwise, it will be set in
        _validate_request().
        """
        self._assertion_params = None
        self._assertion_xml = None
        self._django_request = django_request
        self._relay_state = None
        self._request = None
        self._request_id = None
        self._request_xml = None
        self._request_params = None
        self._response_id = None
        self._saml_request = None
        self._saml_response = None
        self._subject = None
        self._subject_format = 'urn:oasis:names:tc:SAML:2.0:nameid-format:email'
        self._system_params = {
            'ISSUER': saml2idp_metadata.SAML2IDP_CONFIG['issuer'],
        }

    def _validate_request(self):
        """
        Validates the SAML request against the SP configuration of this
        processor. Sub-classes should override this and raise a
        `CannotHandleAssertion` exception if the validation fails.

        Raises:
            CannotHandleAssertion: if the ACS URL specified in the SAML request
                doesn't match the one specified in the processor config.
        """
        request_acs_url = self._request_params['ACS_URL']

        if self._config['acs_url'] != request_acs_url:
            msg = ("couldn't find ACS url '{}' in SAML2IDP_REMOTES "
                   "setting.".format(request_acs_url))
            self._logger.info(msg)
            raise exceptions.CannotHandleAssertion(msg)

    def _validate_user(self):
        """
        Validates the User. Sub-classes should override this and
        throw an CannotHandleAssertion Exception if the validation does not succeed.
        """
        pass

    def can_handle(self, request):
        """
        Returns true if this processor can handle this request.
        """
        self._reset(request)
        # Read the request.
        try:
            self._extract_saml_request()
        except Exception as exc:
            msg = "can't find SAML request in user session: %s" % exc
            self._logger.info(msg)
            raise exceptions.CannotHandleAssertion(msg)

        try:
            self._decode_request()
        except Exception as exc:
            msg = "can't decode SAML request: %s" % exc
            self._logger.info(msg)
            raise exceptions.CannotHandleAssertion(msg)

        try:
            self._parse_request()
        except Exception as exc:
            msg = "can't parse SAML request: %s" % exc
            self._logger.info(msg)
            raise exceptions.CannotHandleAssertion(msg)

        self._validate_request()
        return True

    def generate_response(self):
        """
        Processes request and returns template variables suitable for a response.
        """
        # Build the assertion and response.
        self._validate_user()
        self._build_assertion()
        self._format_assertion()
        self._build_response()
        self._format_response()
        self._encode_response()

        # Return proper template params.
        return self._get_django_response_params()

    def init_deep_link(self, request, sp_config, url):
        """
        Initialize this Processor to make an IdP-initiated call to the SP's
        deep-linked URL.
        """
        self._reset(request, sp_config)
        acs_url = self._config['acs_url']
        # NOTE: The following request params are made up. Some are blank,
        # because they comes over in the AuthnRequest, but we don't have an
        # AuthnRequest in this case:
        # - Destination: Should be this IdP's SSO endpoint URL. Not used in the response?
        # - ProviderName: According to the spec, this is optional.
        self._request_params = {
            'ACS_URL': acs_url,
            'DESTINATION': '',
            'PROVIDER_NAME': '',
        }
        self._relay_state = url
