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
import codex
from misc import get_acs_url


@login_required
def saml_assert(request):
#TODO: Make constants into settings in saml2idp_settings.py

    # Copied verbatim from http://robinelvin.wordpress.com/2009/09/04/saml-with-django/
    # Enable SAML logging if needed for debugging
    # SAML.log(logging.DEBUG, "PySAML.log")

    # The subject of the assertion. Usually an e-mail address or username.
    subject = SAML.Subject(request.user.email,"urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress")

    # The authentication statement which is how the person is proving he really is that person. Usually a password.
    authStatement = SAML.AuthenticationStatement(subject,"urn:oasis:names:tc:SAML:1.0:am:password",None)

    # Create a conditions timeframe of 5 minutes (period in which assertion is valid)
    notBefore = time.strftime("%Y-%m-%dT%H:%M:%SZ",time.gmtime())
    notOnOrAfter = time.strftime("%Y-%m-%dT%H:%M:%SZ",time.gmtime(time.time() + 5))
    conditions = SAML.Conditions(notBefore, notOnOrAfter)

    # Create the actual assertion
    assertion = SAML.Assertion(authStatement, "Test Issuer", conditions)

    if not saml2idp_settings.SAML2IDP_SIGNING:
        return HttpResponse(assertion,  mimetype='text/xml')

    # At this point I have an assertion. To sign the assertion I need to put it
    # into a SAML response object.

    # Open up private key file
    privateKeyFile = open(saml2idp_settings.SAML2IDP_PRIVATE_KEY_FILE, "r")
    privatekey = privateKeyFile.read()
    privateKeyFile.close()

    # Open up the certificate
    certificateFile = open(saml2idp_settings.SAML2IDP_CERTIFICATE_FILE, "r")
    certificate = certificateFile.read()
    certificateFile.close()

    # Sign with the private key but also include the certificate in the SAML response
    response = SAML.Response(assertion, privatekey, certificate)
    return HttpResponse(response,  mimetype='text/xml')

def _get_saml_assertion(user):
    """
    Return a SAML assertion for the user.
    If appropriate, add signing to it.
    """
    # The subject of the assertion. Usually an e-mail address or username.
    subject = SAML.Subject(user.email,"urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress")

    # The authentication statement which is how the person is proving he really is that person. Usually a password.
    authStatement = SAML.AuthenticationStatement(subject,"urn:oasis:names:tc:SAML:1.0:am:password",None)

    # Create a conditions timeframe of 5 minutes (period in which assertion is valid)
    notBefore = time.strftime("%Y-%m-%dT%H:%M:%SZ",time.gmtime())
    notOnOrAfter = time.strftime("%Y-%m-%dT%H:%M:%SZ",time.gmtime(time.time() + 5))
    conditions = SAML.Conditions(notBefore, notOnOrAfter)

    # Create the actual assertion
    assertion = SAML.Assertion(authStatement, "Test Issuer", conditions)

    if not saml2idp_settings.SAML2IDP_SIGNING:
        return assertion.getXML()

    # At this point I have an assertion. To sign the assertion I need to put it
    # into a SAML response object.

    # Open up private key file
    privateKeyFile = open(saml2idp_settings.SAML2IDP_PRIVATE_KEY_FILE, "r")
    privatekey = privateKeyFile.read()
    privateKeyFile.close()

    # Open up the certificate
    certificateFile = open(saml2idp_settings.SAML2IDP_CERTIFICATE_FILE, "r")
    certificate = certificateFile.read()
    certificateFile.close()

    # Sign with the private key but also include the certificate in the SAML response
    signed_assertion = SAML.Response(assertion, privatekey, certificate)
    return signed_assertion.getXML()

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
        #XXX: What do I do with the xml now?
        acs_url = get_acs_url(xml)
        request.session['ACS_URL'] = acs_url
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
    response = forms.CharField(max_length=10000, widget=forms.Textarea(attrs=bigtext))
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
                request.session['SAMLResponse'] = form.cleaned_data['response']
                return redirect('/idp/sso/post/response/')
    else:
        assertion = _get_saml_assertion(request.user)

    response = codex.deflate_and_base64_encode(assertion)
    init = {
        'assertion': assertion,
        'response': response,
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
