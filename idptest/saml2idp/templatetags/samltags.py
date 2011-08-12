"""
Tags that support SAML 2.0 XML.
"""
from django import template

register = template.Library()

@register.inclusion_tag('samltags/assertion.xml')
def assertion_xml(saml_request, assertion, issuer=None):
    return {
        'assertion': assertion,
        'issuer': issuer,
        'saml_request': saml_request,
    }

@register.inclusion_tag('samltags/response.xml')
def response_xml(saml_request, saml_response, assertion, issuer=None, signature=None):
    return {
        'saml_response': saml_response,
        'issuer': issuer,
        'signature': signature,
        'assertion': assertion,
    }

@register.inclusion_tag('samltags/signature.xml')
def signature_xml(signature):
    return {
        'signature': signature,
    }
