"""
XML templates for SAML 2.0
"""
from typing import Iterable, Mapping, Optional

from lxml import etree

from flask_saml2.types import XmlNode
from flask_saml2.utils import cached_property

NAMESPACE_MAP: Mapping[str, str] = {  # Namespace map
    'samlp': 'urn:oasis:names:tc:SAML:2.0:protocol',
    'saml': 'urn:oasis:names:tc:SAML:2.0:assertion',
    'md': 'urn:oasis:names:tc:SAML:2.0:metadata',
    'ds': 'http://www.w3.org/2000/09/xmldsig#',
}


class XmlTemplate:

    namespace = None

    def __init__(self, params: dict = {}):
        self.params = params.copy()

    @cached_property
    def xml(self) -> XmlNode:
        """The XML node this template constructed.
        Generated using :meth:`generate_xml`.
        """
        return self.generate_xml()

    def generate_xml(self):
        raise NotImplementedError

    def get_xml_string(self):
        return etree.tostring(self.xml, method='c14n', exclusive=True).decode('utf-8')

    def element(
        self,
        tag: str,
        *,
        namespace: Optional[str] = None,
        attrs: Optional[Mapping[str, Optional[str]]] = None,
        children: Optional[Iterable[Optional[XmlNode]]] = None,
        text: Optional[str] = None
    ) -> XmlNode:
        """
        Shortcut for creating an ElementTree Element, with optional attributes,
        children, and text.

        :param tag str: tag to give XML element
        :param namespace str: Namespace to use for the element. Defaults to
            :meth:`get_namespace()` if None.
        :param attrs dict: Element attributes. If an attribute value is None,
            the attribute is ignored.
        :param children list: Element children. If an item in children is None,
            the item is ignored.
        :param text str: Element text content, if any.
        :return: xml.etree.ElementTree.Element
        """
        if namespace is None:
            namespace = self.get_namespace()

        tag_name = f'{{{namespace}}}{tag}'
        element = etree.Element(tag_name, nsmap=self.get_namespace_map())

        if attrs is not None:
            for k, v in attrs.items():
                if v is not None:
                    element.set(k, v)

        if children is not None:
            for child in children:
                if child is not None:
                    element.append(child)

        if text is not None:
            element.text = text

        return element

    def get_namespace_map(self) -> Mapping[str, str]:
        return NAMESPACE_MAP

    def get_namespace(self) -> str:
        return self.get_namespace_map()[self.namespace]


class NameIDTemplate(XmlTemplate):
    """
    A ``<NameID>`` node, such as:

    .. code-block:: xml

        <NameID Format="${SUBJECT_FORMAT}" SPNameQualifier="${SP_NAME_QUALIFIER}">
            ${SUBJECT}
        </NameID>
    """
    namespace = 'saml'

    def generate_xml(self):
        return self.element('NameID', attrs={
            'Format': self.params['SUBJECT_FORMAT'],
            'SPNameQualifier': self.params.get('SP_NAME_QUALIFIER'),
        }, text=self.params['SUBJECT'])
