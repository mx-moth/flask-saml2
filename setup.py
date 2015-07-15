# -*- coding: utf-8 -*-
from setuptools import setup
import saml2idp


with open('README.rst') as readme:
    description = readme.read()

setup(
    name='dj-saml-idp',
    version=saml2idp.__version__,
    author='Sebastian Vetter',
    author_email='sebastian@mobify.com',
    description='SAML 2.0 IdP for Django',
    long_description=description,
    install_requires=[
        'Django>=1.4',
        'M2Crypto>=0.20.1',
        'BeautifulSoup>=3.2.0'],
    license='MIT',
    packages=['saml2idp'],
    url='http://github.com/mobify/dj-saml-idp',
    zip_safe=False,
)
