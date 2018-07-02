# -*- coding: utf-8 -*-
from setuptools import find_packages, setup

with open('README.rst') as readme:
    description = readme.read()


with open('flask_saml2/version.py') as version_file:
    version_str = None
    exec(version_file.read())
    assert version_str is not None


setup(
    name='flask-saml2',
    version=version_str,
    author='Tim Heap',
    author_email='tim.heap@tidetech.org',
    description='SAML 2.0 IdP and SP for Flask and Python 3',
    long_description=description,
    install_requires=[
        'Flask>=1.0.0',
        'pyopenssl<18',
        'defusedxml>=0.5.0',
        'signxml>=2.4.0',
        'lxml>=3.8.0',
    ],
    license='MIT',
    packages=find_packages(include=['flask_saml2*']),
    url='http://github.com/timheap/flask-saml2-idp',
    zip_safe=False,
    include_package_data=True,
)
