# -*- coding: utf-8 -*-
from setuptools import setup
import saml2idp


with open('README.rst') as readme:
    description = readme.read()


with open('HISTORY.rst') as history:
    changelog = history.read()


setup(
    name='dj-saml-idp',
    version=saml2idp.__version__,
    author='Basraah',
    author_email='basraaheve@gmail.com',
    description='SAML 2.0 IdP for Django and Python 3',
    long_description='\n\n'.join([description, changelog]),
    install_requires=[
        'Django>=1.11',
        'M2Crypto>=0.29.0',
        'defusedxml>=0.5.0',
        'signxml>=2.4.0',
        'lxml>=3.8.0',
    ],
    license='MIT',
    packages=['saml2idp'],
    url='http://github.com/basraah/dj-saml-idp',
    zip_safe=False,
    include_package_data=True,
)
