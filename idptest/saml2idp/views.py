import time
import SAML
from django import forms
from django.conf import settings
from django.contrib.auth.decorators import login_required
from django.contrib.auth.views import auth_login
from django.http import HttpResponse
from django.shortcuts import render_to_response, redirect
from django.views.decorators.csrf import csrf_view_exempt, csrf_response_exempt
import saml2idp_settings
import base64
import codex
from misc import get_acs_url, parse_saml_request
import signing
from django.template import Context, Template
import xml


@login_required
#def saml_assert(request):
##TODO: Make constants into settings in saml2idp_settings.py
#
#    # Copied verbatim from http://robinelvin.wordpress.com/2009/09/04/saml-with-django/
#    # Enable SAML logging if needed for debugging
#    # SAML.log(logging.DEBUG, "PySAML.log")
#
#    # The subject of the assertion. Usually an e-mail address or username.
#    subject = SAML.Subject(request.user.email,"urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress")
#
#    # The authentication statement which is how the person is proving he really is that person. Usually a password.
#    authStatement = SAML.AuthenticationStatement(subject,"urn:oasis:names:tc:SAML:1.0:am:password",None)
#
#    # Create a conditions timeframe of 5 minutes (period in which assertion is valid)
#    notBefore = time.strftime("%Y-%m-%dT%H:%M:%SZ",time.gmtime())
#    notOnOrAfter = time.strftime("%Y-%m-%dT%H:%M:%SZ",time.gmtime(time.time() + 5))
#    conditions = SAML.Conditions(notBefore, notOnOrAfter)
#
#    # Create the actual assertion
#    assertion = SAML.Assertion(authStatement, "Test Issuer", conditions)
#
#    if not saml2idp_settings.SAML2IDP_SIGNING:
#        return HttpResponse(assertion,  mimetype='text/xml')
#
#    # At this point I have an assertion. To sign the assertion I need to put it
#    # into a SAML response object.
#
#    # Open up private key file
#    privateKeyFile = open(saml2idp_settings.SAML2IDP_PRIVATE_KEY_FILE, "r")
#    privatekey = privateKeyFile.read()
#    privateKeyFile.close()
#
#    # Open up the certificate
#    certificateFile = open(saml2idp_settings.SAML2IDP_CERTIFICATE_FILE, "r")
#    certificate = certificateFile.read()
#    certificateFile.close()
#
#    # Sign with the private key but also include the certificate in the SAML response
#    response = SAML.Response(assertion, privatekey, certificate)
#    return HttpResponse(response,  mimetype='text/xml')

#def _get_saml_response_xml(request):
#    """
#    Return a SAML assertion for the user.
#    If appropriate, add signing to it.
#    """
#    saml_request = {
#        'id': request.session['request_id'],
#        'acs_url': request.session['ACS_URL'],
#        'audience': request.session['ACS_URL'], #HACK
#    }
#    saml_response = {
#        'id': '_2972e82c07bb5453956cc11fb19cad97ed26ff8bb4',
#        'issue_instant': '2011-08-11T23:38:34Z',
#    }
#    assertion = {
#        'id': '_7ccdda8bc6b328570c03b218d7521772998da45374',
#        'issue_instant': '2011-08-11T23:38:34Z',
#        'not_before': '2011-08-11T23:38:04Z',
#        'not_on_or_after': '2011-08-11T23:43:34Z',
#        'session': {
#            'index': '_ee277dff4e2db138d25dfcea7ccdf1d1db9ddea3f5',
#            'not_on_or_after': '2011-08-12T07:38:34Z',
#        },
#        'subject': { 'email': 'randomuser@example.com' },
#    }
#    issuer = 'http://127.0.0.1:8000/' #TODO: Make this a setting?
#
#    if saml2idp_settings.SAML2IDP_SIGNING:
#        # Sign the assertion.
#        signer = signing.Signer()
#        assertion['signature'] = signer.get_assertion_signature(saml_request, assertion, issuer)
#
#        # Now, sign the response.
#        response_signature = signer.get_response_signature(saml_request, saml_response, assertion, issuer)
#
#    # Finally, generate XML.
#    t = Template(
#        '{% load samltags %}'
#        '{% response_xml saml_request saml_response assertion issuer signature %}'
#    )
#    c = Context({
#        'saml_request': saml_request,
#        'saml_response': saml_response,
#        'assertion': assertion,
#        'issuer': issuer,
#        'signature': response_signature,
#
#    })
#    response_xml = t.render(c)
#    return response_xml

def _get_saml_response_xml(request):
    """
    Return a SAML assertion for the user.
    If appropriate, add signing to it.
    """
    saml_request = {
        'id': request.session['request_id'],
        'acs_url': request.session['ACS_URL'],
        'audience': request.session['ACS_URL'], #HACK
    }
    saml_response = {
        'id': '_2972e82c07bb5453956cc11fb19cad97ed26ff8bb4',
        'issue_instant': '2011-08-11T23:38:34Z',
    }
    assertion = {
        'id': '_7ccdda8bc6b328570c03b218d7521772998da45374',
        'issue_instant': '2011-08-11T23:38:34Z',
        'not_before': '2011-08-11T23:38:04Z',
        'not_on_or_after': '2011-08-11T23:43:34Z',
        'session': {
            'index': '_ee277dff4e2db138d25dfcea7ccdf1d1db9ddea3f5',
            'not_on_or_after': '2011-08-12T07:38:34Z',
        },
        'subject': { 'email': 'randomuser@example.com' },
    }
    issuer = 'http://127.0.0.1:8000/' #TODO: Make this a setting?

    assertion_xml = xml.get_assertion_xml(saml_request, assertion, issuer, signed=saml2idp_settings.SAML2IDP_SIGNING)
    response_xml = xml.get_response_xml(saml_request, saml_response, assertion, issuer, signed=saml2idp_settings.SAML2IDP_SIGNING)
    return response_xml


#def _get_saml_assertion_pysaml(user):
#    """
#    Returns a SAML assertion for the user. Based on samltags tab library.
#    """
#    # The subject of the assertion. Usually an e-mail address or username.
#    subject = SAML.Subject(user.email,"urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress")
#
#    # The authentication statement which is how the person is proving he really is that person. Usually a password.
#    authStatement = SAML.AuthenticationStatement(subject,"urn:oasis:names:tc:SAML:1.0:am:password",None)
#
#    # Create a conditions timeframe of 5 minutes (period in which assertion is valid)
#    notBefore = time.strftime("%Y-%m-%dT%H:%M:%SZ",time.gmtime())
#    notOnOrAfter = time.strftime("%Y-%m-%dT%H:%M:%SZ",time.gmtime(time.time() + 5))
#    conditions = SAML.Conditions(notBefore, notOnOrAfter)
#
#    # Create the actual assertion
#    assertion = SAML.Assertion(authStatement, "Test Issuer", conditions)
#
#    if not saml2idp_settings.SAML2IDP_SIGNING:
#        return assertion.getXML()
#
#    # At this point I have an assertion. To sign the assertion I need to put it
#    # into a SAML response object.
#
#    # Open up private key file
#    privateKeyFile = open(saml2idp_settings.SAML2IDP_PRIVATE_KEY_FILE, "r")
#    privatekey = privateKeyFile.read()
#    privateKeyFile.close()
#
#    # Open up the certificate
#    certificateFile = open(saml2idp_settings.SAML2IDP_CERTIFICATE_FILE, "r")
#    certificate = certificateFile.read()
#    certificateFile.close()
#
#    # Sign with the private key but also include the certificate in the SAML response
#    signed_assertion = SAML.Response(assertion, privatekey, certificate)
#    return signed_assertion.getXML()


@csrf_view_exempt
def sso_handle_incoming_post_request(request):
    """
    A Service Point has just POSTed an auth request.
    """
    #TODO: Do we need to actually do anything with the POST['Request']?
    #TODO: Break this out into separate GET/POST views, or rename.
    if request.method == 'GET':
        token = request.GET.get('RelayState', None)
        saml_request = request.GET.get('SAMLRequest', None)
        xml = codex.decode_base64_and_inflate(saml_request)
        ##XXX: What do I do with the xml now?
        #acs_url = get_acs_url(xml)

        request.session.update(parse_saml_request(xml))
    else:
        token = request.POST.get('RelayState', None)
    request.session['RelayState'] = token
    tv = {
        'token': token,
        'login_url': settings.LOGIN_URL,
    }
    return render_to_response('saml2idp/sso_incoming_request.html', tv)

class PreviewForm(forms.Form):
    bigtext = { 'rows': 8, 'cols': 80 }
    assertion = forms.CharField(max_length=10000, widget=forms.Textarea(attrs=bigtext))
    encoded = forms.CharField(max_length=10000, widget=forms.Textarea(attrs=bigtext))
    is_ok = forms.BooleanField(required=False)

@login_required
@csrf_view_exempt
def sso_post_response_preview(request):
    """
    Preview the assertion, to allow changes prior to submitting.
    Mainly for debugging.
    """
    if request.method == 'POST':
        form = PreviewForm(request.POST)
        if form.is_valid():
            assertion = form.cleaned_data['assertion']
            if form.cleaned_data['is_ok']:
                request.session['Assertion'] = assertion
                request.session['SAMLResponse'] = form.cleaned_data['encoded']
                return redirect('/idp/sso/post/response/')
    else:
        assertion = _get_saml_response_xml(request)

    encoded = base64.b64encode(assertion)
    init = {
        'assertion': assertion,
        'encoded': encoded,
    }
    form = PreviewForm(initial=init)

    tv = {
        'form': form,
    }
    return render_to_response('saml2idp/sso_post_response_preview.html', tv)

@login_required
@csrf_response_exempt
def sso_post_response(request):
    """
    Returns an HTML form that will POST back to the Service Point.
    """
    #TODO: Only allow this view to accept POSTs from trusted sites.
    #TODO: Will the @login_required work right? If not, we need to 'remember'
    #      the POST data and do the authentication in this view.
    #assertion = _get_saml_assertion(request.user)
    #saml_response = codex.deflate_and_base64_encode(assertion)
    assertion = request.session.get('Assertion')
    saml_response = request.session.get('SAMLResponse', None)

    token = request.session.get('RelayState', None)
    acs_url = request.session.get('ACS_URL', saml2idp_settings.SP_RESPONSE_URL)
    tv = {
        'response_url': acs_url,
        'assertion': assertion,
        'saml_response': saml_response,
        'token': token,
    }
    return render_to_response('saml2idp/sso_post_response.html', tv)
