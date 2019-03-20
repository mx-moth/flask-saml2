#!/usr/bin/env python3
from setuptools import find_packages, setup

with open('README.rst') as readme:
    readme = readme.read()

with open('flask_saml2/version.py') as version_file:
    version_str = None
    exec(version_file.read())
    assert version_str is not None


setup_kwargs = dict(
    name='flask-saml2',
    version=version_str,
    license='MIT',

    author='Tim Heap',
    author_email='tim.heap@tidetech.org',

    description='SAML 2.0 IdP and SP for Flask and Python 3',
    long_description=readme,
    url='http://github.com/timheap/flask-saml2',

    install_requires=[
        'attrs>=18.1.0',
        'Flask>=1.0.0',
        'signxml>=2.4.0',
        'lxml>=3.8.0',
        'pyopenssl<18',
        'defusedxml>=0.5.0',
        'pytz>=0',
        'iso8601~=0.1.12',
    ],
    packages=find_packages(include=['flask_saml2*']),
    include_package_data=True,
    zip_safe=False,

    classifiers=[
        'Development Status :: 3 - Alpha',
        'Environment :: Web Environment',
        'Framework :: Flask',
        'License :: OSI Approved :: MIT License',
        'Programming Language :: Python :: 3',
        'Programming Language :: Python :: 3.6',
        'Programming Language :: Python :: 3 :: Only',
        'Topic :: Security',
        'Topic :: System :: Systems Administration :: Authentication/Directory',
    ],
)


if __name__ == '__main__':
    setup(**setup_kwargs)
