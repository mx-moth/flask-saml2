from setuptools import setup

setup(
    name = 'saml2idp',
    version = '0.15',
    author = 'John Samuel Anderson',
    author_email = 'john@andersoninnovative.com',
    description = 'SAML 2.0 IdP for Django',
    long_description = 'SAML 2.0 Identity Provider app for Django projects.',
    install_requires = [
        'M2Crypto>=0.20.1',
        'BeautifulSoup>=3.2.0',
    ],
    license = 'MIT',
    packages = ['saml2idp', 'saml2idp.tests'],
    package_dir = {'saml2idp': 'idptest/saml2idp'},
    package_data = {'saml2idp': ['templates/saml2idp/*.html']},
    url = 'http://code.google.com/p/django-saml2-idp/',
    zip_safe = True,
)
