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
        'saml_request': saml_request,
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

@register.tag
def indent(parser, token):
    spaces = int(token.split_contents()[1])
    nodelist = parser.parse(('endindent',))
    parser.delete_first_token()
    return Indent(nodelist, spaces)

class Indent(template.Node):
    def __init__(self, nodelist, spaces):
        self.nodelist = nodelist
        self.spaces = ' ' * spaces
    def render(self, context):
        output = self.nodelist.render(context)
        return '\n'.join([ self.spaces + line for line in output.split('\n') ])
