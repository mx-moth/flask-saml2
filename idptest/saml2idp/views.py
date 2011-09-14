# Python imports:
import base64
import logging
import time
import uuid
# Django/other library imports:
from django.contrib import auth
from django.contrib.auth.decorators import login_required
from django.shortcuts import render_to_response, redirect
from django.views.decorators.csrf import csrf_view_exempt, csrf_response_exempt
# saml2idp app imports:
import codex
import saml2idp_settings
import validation
import xml_parse
import xml_render

MINUTES = 60
HOURS = 60 * MINUTES

def get_email(request):
    """
    Returns the user's email address for standard Django user accounts.
    If you have a special user type object, you probably will need to write
    a function with this signature, and specify that function as an optional
    parameter to the login_continue view. See that view for more info.
    """
    return request.user.email

def get_random_id():
    random_id = uuid.uuid4().hex
    return random_id

def get_time_string(delta=0):
    return time.strftime("%Y-%m-%dT%H:%M:%SZ",time.gmtime(time.time() + delta))

@csrf_view_exempt
def login_post(request):
    """
    SALESFORCE SPECIFIC.
    Receives a *POST* SAML 2.0 AuthnRequest from a Service Point and
    stores it in the session prior to enforcing login.
    """
    if request.method != 'POST':
        raise Exception('Not a POST.') #TODO: Return a SAML 2.0 Error Assertion???
    # Store these values now, because Django's login cycle won't preserve them.
    request.session['SAMLRequest'] = request.POST['SAMLRequest']
    request.session['RelayState'] = request.POST['RelayState']
    return redirect('login_continue')


@login_required
@csrf_response_exempt
def login_continue(request, *args, **kwargs):
    """
    SALESFORCE SPECIFIC.
    Presents a SAML 2.0 Assertion for POSTing back to the Service Point.
    """
    # First, handle any optional parameters.
    get_email_function = kwargs.get('get_email_function', get_email)
    validate_user_function = kwargs.get('validate_user_function', validation.validate_user)

    # Retrieve the AuthnRequest from the session.
    msg = request.session['SAMLRequest']
    relay_state = request.session['RelayState']

    # Read the request.
    xml = base64.b64decode(msg) # SALESFORCE
    logging.debug('login view received xml: ' + xml)
    request_params = xml_parse.parse_request(xml)

    validation.validate_request(request_params)

    # Just in case downstream code wants to filter by some user criteria:
    try:
        validate_user_function(request)
    except:
        return render_to_response('saml2idp/invalid_user.html')

    # Build the Assertion.
    system_params = {
        'ISSUER': saml2idp_settings.SAML2IDP_ISSUER,
    }

    # Guess at the Audience.
    audience = request_params['DESTINATION']
    if not audience:
        audience = request_params['PROVIDER_NAME']
    audience = 'https://saml.salesforce.com' # SALESFORCE

    email = get_email_function(request)

    assertion_id = get_random_id()
    session_index = request.session.session_key
    assertion_params = {
        'ASSERTION_ID': assertion_id,
        'ASSERTION_SIGNATURE': '', # it's unsigned
        'AUDIENCE': audience, # YAGNI? See note in xml_templates.py.
        'AUTH_INSTANT': get_time_string(),
        'ISSUE_INSTANT': get_time_string(),
        'NOT_BEFORE': get_time_string(-1 * HOURS), #TODO: Make these settings.
        'NOT_ON_OR_AFTER': get_time_string(15 * MINUTES),
        'SESSION_INDEX': session_index,
        'SESSION_NOT_ON_OR_AFTER': get_time_string(8 * HOURS),
        'SP_NAME_QUALIFIER': audience,
        'SUBJECT_EMAIL': email
    }
    assertion_params.update(system_params)
    assertion_params.update(request_params)

    # Build the SAML Response.
    assertion_xml = xml_render.get_assertion_salesforce_xml(assertion_params, signed=True)
    response_id = get_random_id()
    response_params = {
        'ASSERTION': assertion_xml,
        'ISSUE_INSTANT': get_time_string(),
        'RESPONSE_ID': response_id,
        'RESPONSE_SIGNATURE': '', # initially unsigned
    }
    response_params.update(system_params)
    response_params.update(request_params)

    # Present the Response. (Because Django has already enforced login.)
    acs_url = request_params['ACS_URL']

    response_xml = xml_render.get_response_xml(response_params, signed=True)
    encoded_xml = codex.nice64(response_xml)
    autosubmit = saml2idp_settings.SAML2IDP_AUTOSUBMIT
    tv = {
        'acs_url': acs_url,
        'saml_response': encoded_xml,
        'relay_state': relay_state,
        'autosubmit': autosubmit,
    }
    return render_to_response('saml2idp/login.html', tv)

@login_required
@csrf_view_exempt
@csrf_response_exempt
def login(request):
    """
    GOOGLE APPS SPECIFIC.
    Receives a *GET* SAML 2.0 AuthnRequest from a Service Point and
    presents a SAML 2.0 Assertion for POSTing back to the Service Point.
    """
    #TODO: Probably, we'll need some optional parameters, like in login_continue().

    # Receive the AuthnRequest.
    if request.method != 'GET':
        # Django will mess up POST data, due to @login_required.
        raise Exception('Not a GET.') #TODO: Return a SAML 2.0 Error Assertion???

    msg = request.GET['SAMLRequest']
    relay_state = request.GET['RelayState']

    # Read the request.
    xml = codex.decode_base64_and_inflate(msg)
    logging.debug('login view received xml: ' + xml)
    request_params = xml_parse.parse_request(xml)

    validation.validate_request(request_params)

    # Build the Assertion.
    system_params = {
        'ISSUER': saml2idp_settings.SAML2IDP_ISSUER,
    }

    # Guess at the Audience.
    #audience = request_params['DESTINATION']
    #if not audience:
    audience = request_params['PROVIDER_NAME']

    email = request.user.email

    assertion_id = get_random_id()
    session_index = request.session.session_key
    assertion_params = {
        'ASSERTION_ID': assertion_id,
        'ASSERTION_SIGNATURE': '', # it's unsigned
        'AUDIENCE': audience, # YAGNI? See note in xml_templates.py.
        'AUTH_INSTANT': get_time_string(),
        'ISSUE_INSTANT': get_time_string(),
        'NOT_BEFORE': get_time_string(-1 * HOURS), #TODO: Make these settings.
        'NOT_ON_OR_AFTER': get_time_string(15 * MINUTES),
        'SESSION_INDEX': session_index,
        'SESSION_NOT_ON_OR_AFTER': get_time_string(8 * HOURS),
        'SP_NAME_QUALIFIER': audience,
        'SUBJECT_EMAIL': email
    }
    assertion_params.update(system_params)
    assertion_params.update(request_params)

    # Build the SAML Response.
    assertion_xml = xml_render.get_assertion_google_xml(assertion_params, signed=True)
    response_id = get_random_id()
    response_params = {
        'ASSERTION': assertion_xml,
        'ISSUE_INSTANT': get_time_string(),
        'RESPONSE_ID': response_id,
        'RESPONSE_SIGNATURE': '', # initially unsigned
    }
    response_params.update(system_params)
    response_params.update(request_params)

    # Present the Response. (Because Django has already enforced login.)
    acs_url = request_params['ACS_URL']

    response_xml = xml_render.get_response_xml(response_params, signed=True)
    encoded_xml = codex.nice64(response_xml)
    autosubmit = saml2idp_settings.SAML2IDP_AUTOSUBMIT
    tv = {
        'acs_url': acs_url,
        'saml_response': encoded_xml,
        'relay_state': relay_state,
        'autosubmit': autosubmit,
    }
    return render_to_response('saml2idp/login.html', tv)

@csrf_view_exempt
def logout(request):
    """
    Receives a SAML 2.0 LogoutRequest from a Service Point,
    logs out the user and returns a standard logged-out page.
    """
    auth.logout(request)
    tv = {}
    return render_to_response('saml2idp/logged_out.html', tv)
