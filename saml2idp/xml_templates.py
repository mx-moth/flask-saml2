"""
XML templates for SAML 2.0
"""
import lxml.etree as ET


class XmlTemplate:
    NS_MAP = {  # Namespace map
        'samlp': 'urn:oasis:names:tc:SAML:2.0:protocol',
        'saml': 'urn:oasis:names:tc:SAML:2.0:assertion',
        'ds': 'http://www.w3.org/2000/09/xmldsig#',
    }

    def __init__(self, params: dict = None):
        if params is None:
            self.params = {}
        else:
            self.params = params
        self.namespace = ''
        self._xml = None

    def generate_xml(self):
        raise NotImplementedError

    @property
    def xml(self) -> ET.Element:
        if self._xml is None:
            self.generate_xml()
        return self._xml

    def get_xml_string(self):
        if self.xml is None:
            raise ValueError("XML has not been generated yet")
        return ET.tostring(self.xml, method='c14n', exclusive=True).decode('utf-8')

    def create_element(self, _tag, **kwargs):
        """
        Create an etree element
        :param _tag: str tag to give XML element
        :param kwargs: element attributes
        :return: xml.etree.ElementTree.Element
        """
        ele = ET.Element('{' + self.get_namespace() + '}' + _tag, nsmap=self.NS_MAP)
        for k, v in kwargs.items():
            ele.set(k, v)
        return ele

    def sub_element(self, _parent, _tag, **kwargs):
        ele = ET.SubElement(_parent, '{' + self.get_namespace() + '}' + _tag, nsmap=self.NS_MAP)
        for k, v in kwargs.items():
            ele.set(k, v)
        return ele

    def get_namespace(self):
        return self.NS_MAP[self.namespace]


class SignedInfoTemplate(XmlTemplate):
    def __init__(self, params):
        super(SignedInfoTemplate, self).__init__(params)
        self.namespace = 'ds'

    def generate_xml(self):
        si = self.create_element('SignedInfo')
        si.append(self._get_canon_method())
        si.append(self._get_signature_method())
        si.append(self._get_reference())
        self._xml = si

    def _get_tranforms(self):
        tfs = self.create_element('Transforms')
        tfs.append(self.create_element('Transform', Algorithm='http://www.w3.org/2000/09/xmldsig#enveloped-signature'))
        tfs.append(self.create_element('Transform', Algorithm='http://www.w3.org/2001/10/xml-exc-c14n#'))
        return tfs

    def _get_reference(self):
        rf = self.create_element('Reference', URI='#' + self.params['REFERENCE_URI'])

        rf.append(self._get_tranforms())
        self.sub_element(rf, 'DigestMethod', Algorithm='http://www.w3.org/2000/09/xmldsig#sha1')
        dv = self.sub_element(rf, 'DigestValue')
        dv.text = self.params['SUBJECT_DIGEST']
        return rf

    def _get_signature_method(self):
        return self.create_element('SignatureMethod', Algorithm='http://www.w3.org/2000/09/xmldsig#rsa-sha1')

    def _get_canon_method(self):
        return self.create_element('CanonicalizationMethod', Algorithm='http://www.w3.org/2001/10/xml-exc-c14n#')

    """
    Not used, just left for reference
        <ds:SignedInfo xmlns:ds="http://www.w3.org/2000/09/xmldsig#">
            <ds:CanonicalizationMethod Algorithm="http://www.w3.org/2001/10/xml-exc-c14n#"></ds:CanonicalizationMethod>
            <ds:SignatureMethod Algorithm="http://www.w3.org/2000/09/xmldsig#rsa-sha1"></ds:SignatureMethod>
            <ds:Reference URI="#${REFERENCE_URI}">
                <ds:Transforms>
                    <ds:Transform Algorithm="http://www.w3.org/2000/09/xmldsig#enveloped-signature"></ds:Transform>
                    <ds:Transform Algorithm="http://www.w3.org/2001/10/xml-exc-c14n#"></ds:Transform>
                </ds:Transforms>
                <ds:DigestMethod Algorithm="http://www.w3.org/2000/09/xmldsig#sha1"></ds:DigestMethod>
                <ds:DigestValue>${SUBJECT_DIGEST}</ds:DigestValue>
            </ds:Reference>
        </ds:SignedInfo>
    """


class SignatureTemplate(XmlTemplate):
    def __init__(self, params):
        super(SignatureTemplate, self).__init__(params)
        self.namespace = 'ds'

    def generate_xml(self):
        si = self.create_element('Signature')
        si.append(self.params['SIGNED_INFO'])
        si.append(self._get_signature_value())
        si.append(self._get_key_info())
        self._xml = si

    def _get_signature_value(self):
        sv = self.create_element('SignatureValue')
        sv.text = self.params['RSA_SIGNATURE']
        return sv

    def _get_key_info(self):
        ki = self.create_element('KeyInfo')
        x5d = self.sub_element(ki, 'X509Data')
        x5c = self.sub_element(x5d, 'X509Certificate')
        x5c.text = self.params['CERTIFICATE']
        return ki
    """
    <ds:Signature xmlns:ds="http://www.w3.org/2000/09/xmldsig#">
            ${SIGNED_INFO}
        <ds:SignatureValue>${RSA_SIGNATURE}</ds:SignatureValue>
        <ds:KeyInfo>
            <ds:X509Data>
                <ds:X509Certificate>${CERTIFICATE}</ds:X509Certificate>
            </ds:X509Data>
        </ds:KeyInfo>
    </ds:Signature>
    """


class AttributeTemplate(XmlTemplate):
    def __init__(self, params):
        super(AttributeTemplate, self).__init__(params)
        self.namespace = 'saml'

    def generate_xml(self):
        attr = self.create_element('Attribute', Name=self.params['ATTRIBUTE_NAME'],
                                   NameFormat='urn:oasis:names:tc:SAML:2.0:attrname-format:basic')

        av = self.sub_element(attr, 'AttributeValue')
        av.text = self.params['ATTRIBUTE_VALUE']

        self._xml = attr

    """
        <saml:Attribute Name="${ATTRIBUTE_NAME}" NameFormat="urn:oasis:names:tc:SAML:2.0:attrname-format:basic">
            <saml:AttributeValue>${ATTRIBUTE_VALUE}</saml:AttributeValue>
        </saml:Attribute>
    """


class AttributeStatementTemplate(XmlTemplate):
    def __init__(self, params):
        super(AttributeStatementTemplate, self).__init__(params)
        self.namespace = 'saml'

    def generate_xml(self):
        attributes = self.params.get('ATTRIBUTES', {})
        if len(attributes) < 1:
            self._xml = None
            return
        self._xml = self.create_element('AttributeStatement')

        for name, value in attributes.items():
            subs = {'ATTRIBUTE_NAME': name, 'ATTRIBUTE_VALUE': value}
            self._xml.append(AttributeTemplate(subs).xml)
    """
        <saml:AttributeStatement>
        ${ATTRIBUTES}
        </saml:AttributeStatement>
    """


class SubjectTemplate(XmlTemplate):
    def __init__(self, params):
        super(SubjectTemplate, self).__init__(params)
        self.namespace = 'saml'

    def generate_xml(self):
        subj = self.create_element('Subject')
        subj.append(self._get_name_id_xml())
        subj.append(self._get_subject_conf_xml())
        self._xml = subj

    def _get_name_id_xml(self):
        ni = self.create_element('NameID', Format=self.params['SUBJECT_FORMAT'],
                                 SPNameQualifier=self.params['SP_NAME_QUALIFIER'])
        ni.text = self.params['SUBJECT']
        return ni

    def _get_subject_conf_xml(self):
        sc = self.create_element('SubjectConfirmation', Method='urn:oasis:names:tc:SAML:2.0:cm:bearer')
        scd = self.sub_element(sc, 'SubjectConfirmationData')
        if 'REQUEST_ID' in self.params:
            scd.set('InResponseTo', self.params['REQUEST_ID'])

        scd.set('NotOnOrAfter', self.params['NOT_ON_OR_AFTER'])
        scd.set('Recipient', self.params['ACS_URL'])
        return sc
    """
        <saml:Subject>
            <saml:NameID Format="${SUBJECT_FORMAT}" SPNameQualifier="${SP_NAME_QUALIFIER}">
            ${SUBJECT}
            </saml:NameID>
            <saml:SubjectConfirmation Method="urn:oasis:names:tc:SAML:2.0:cm:bearer">
                <saml:SubjectConfirmationData 
                ${IN_RESPONSE_TO}
                NotOnOrAfter="${NOT_ON_OR_AFTER}" Recipient="${ACS_URL}"></saml:SubjectConfirmationData>
            </saml:SubjectConfirmation>
        </saml:Subject>
    """


class AssertionTemplate(XmlTemplate):
    def __init__(self, params):
        super(AssertionTemplate, self).__init__(params)
        self.subject_statement = None
        self.attribute_statement = None

    def generate_xml(self):
        # Check if the subtemplate values are set, allow users to define their own
        if self.subject_statement is None:
            self.subject_statement = SubjectTemplate(self.params).xml
        if self.attribute_statement is None:
            self.attribute_statement = AttributeStatementTemplate(self.params).xml
        self._xml = self.generate_assertion_xml()

    def generate_assertion_xml(self):
        raise NotImplementedError

    def add_signature(self, signature: ET.Element):
        raise NotImplementedError


class AssertionGoogleAppsTemplate(AssertionTemplate):
    def __init__(self, params):
        super(AssertionGoogleAppsTemplate, self).__init__(params)
        self.namespace = 'saml'

    def generate_assertion_xml(self):
        asr = self.create_element('Assertion')
        asr.set('ID', self.params['ASSERTION_ID'])
        asr.set('IssueInstant', self.params['ISSUE_INSTANT'])
        asr.set('Version', '2.0')

        issuer = self.sub_element(asr, 'Issuer')
        issuer.text = self.params['ISSUER']

        asr.append(self.subject_statement)

        asr.append(self._get_conditions())
        asr.append(self._get_authn_context())
        if self.attribute_statement is not None:
            asr.append(self.attribute_statement)
        return asr

    def _get_conditions(self):
        return self.create_element('Conditions', NotBefore=self.params['NOT_BEFORE'],
                                   NotOnOrAfter=self.params['NOT_ON_OR_AFTER'])

    def _get_authn_context(self):
        authn = self.create_element('AuthnStatement', AuthnInstant=self.params['AUTH_INSTANT'])
        ctx = self.sub_element(authn, 'AuthnContext')
        ctxref = self.sub_element(ctx, 'AuthnContextClassRef')
        ctxref.text = 'urn:oasis:names:tc:SAML:2.0:ac:classes:Password'
        return authn

    def add_signature(self, signature):
        self._xml.insert(1, signature)

    """
    # Minimal assertion for Google Apps:
    ASSERTION_GOOGLE_APPS = (
        '<saml:Assertion xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion" '
                'ID="${ASSERTION_ID}" '
                'IssueInstant="${ISSUE_INSTANT}" '
                'Version="2.0">'
            '<saml:Issuer>${ISSUER}</saml:Issuer>'
            '${ASSERTION_SIGNATURE}'
            '${SUBJECT_STATEMENT}'
            '<saml:Conditions NotBefore="${NOT_BEFORE}" NotOnOrAfter="${NOT_ON_OR_AFTER}">'
            '</saml:Conditions>'
            '<saml:AuthnStatement AuthnInstant="${AUTH_INSTANT}"'
                '>'
                '<saml:AuthnContext>'
                    '<saml:AuthnContextClassRef>urn:oasis:names:tc:SAML:2.0:ac:classes:Password</saml:AuthnContextClassRef>'
                '</saml:AuthnContext>'
            '</saml:AuthnStatement>'
            '${ATTRIBUTE_STATEMENT}'
        '</saml:Assertion>'
    )
    """


class AssertionSalesforceTemplate(AssertionTemplate):
    def __init__(self, params):
        super(AssertionSalesforceTemplate, self).__init__(params)
        self.namespace = 'saml'

    def generate_assertion_xml(self):
        asr = self.create_element('Assertion')
        asr.set('ID', self.params['ASSERTION_ID'])
        asr.set('IssueInstant', self.params['ISSUE_INSTANT'])
        asr.set('Version', '2.0')

        issuer = self.sub_element(asr, 'Issuer')
        issuer.text = self.params['ISSUER']

        asr.append(self.subject_statement)

        asr.append(self._get_conditions())
        asr.append(self._get_authn_context())
        if self.attribute_statement is not None:
            asr.append(self.attribute_statement)
        return asr

    def _get_conditions(self):
        cdn = self.create_element('Conditions', NotBefore=self.params['NOT_BEFORE'],
                                  NotOnOrAfter=self.params['NOT_ON_OR_AFTER'])

        adr = self.sub_element(cdn, 'AudienceRestriction')
        ad = self.sub_element(adr, 'Audience')
        ad.text = self.params['AUDIENCE']
        return cdn

    def _get_authn_context(self):
        authn = self.create_element('AuthnStatement', AuthnInstant=self.params['AUTH_INSTANT'])
        ctx = self.sub_element(authn, 'AuthnContext')
        ctxref = self.sub_element(ctx, 'AuthnContextClassRef')
        ctxref.text = 'urn:oasis:names:tc:SAML:2.0:ac:classes:Password'
        return authn

    def add_signature(self, signature):
        self._xml.insert(1, signature)

    """
    # Minimal assertion for SalesForce:
    ASSERTION_SALESFORCE = (
        '<saml:Assertion xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion" '
                'ID="${ASSERTION_ID}" '
                'IssueInstant="${ISSUE_INSTANT}" '
                'Version="2.0">'
            '<saml:Issuer>${ISSUER}</saml:Issuer>'
            '${ASSERTION_SIGNATURE}'
            '${SUBJECT_STATEMENT}'
            '<saml:Conditions NotBefore="${NOT_BEFORE}" NotOnOrAfter="${NOT_ON_OR_AFTER}">'
                '<saml:AudienceRestriction>'
                    '<saml:Audience>${AUDIENCE}</saml:Audience>'
                '</saml:AudienceRestriction>'
            '</saml:Conditions>'
            '<saml:AuthnStatement AuthnInstant="${AUTH_INSTANT}"'
                '>'
                '<saml:AuthnContext>'
                    '<saml:AuthnContextClassRef>urn:oasis:names:tc:SAML:2.0:ac:classes:Password</saml:AuthnContextClassRef>'
                '</saml:AuthnContext>'
            '</saml:AuthnStatement>'
            '${ATTRIBUTE_STATEMENT}'
        '</saml:Assertion>'
    )
    """


class ResponseTemplate(XmlTemplate):
    def __init__(self, params, assertion):
        super(ResponseTemplate, self).__init__(params)
        self.namespace = 'samlp'
        self.assertion = assertion

    def generate_xml(self):
        r = self.create_element('Response')
        r.set('Destination', self.params['ACS_URL'])
        r.set('ID', self.params['RESPONSE_ID'])
        if 'IN_RESPONSE_TO' in self.params:
            r.set('InResponseTo', self.params['IN_RESPONSE_TO'])
        r.set('IssueInstant', self.params['ISSUE_INSTANT'])
        r.set('Version', '2.0')

        r.append(self._get_issuer())
        r.append(self._get_status())
        r.append(self.assertion)

        self._xml = r

    def add_signature(self, signature_xml):
        self.xml.insert(1, signature_xml)

    def _get_issuer(self):
        i = ET.Element('{' + self.NS_MAP['saml'] + '}Issuer')
        i.text = self.params['ISSUER']
        return i

    def _get_status(self):
        s = self.create_element('Status')
        self.sub_element(s, 'StatusCode', Value='urn:oasis:names:tc:SAML:2.0:status:Success')
        return s
    """
    # Minimal response:
        <samlp:Response xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol" 
                        Destination="${ACS_URL}" 
                        ID="${RESPONSE_ID}" 
                        ${IN_RESPONSE_TO}
                        IssueInstant="${ISSUE_INSTANT}" 
                        Version="2.0">
            <saml:Issuer xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion">${ISSUER}</saml:Issuer>
            ${RESPONSE_SIGNATURE}
            <samlp:Status>
                <samlp:StatusCode Value="urn:oasis:names:tc:SAML:2.0:status:Success"></samlp:StatusCode>
            </samlp:Status>
            ${ASSERTION}
        </samlp:Response>
    """
