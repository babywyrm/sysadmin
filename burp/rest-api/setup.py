#!/usr/bin/env python

import os
import sys

from PyBurprestapi import __version__ as version

try:
    from setuptools import setup
except ImportError:
    from distutils.core import setup

with open('README.rst', 'r') as f:
    readme = f.read()

# Publish helper
if sys.argv[-1] == 'build':
    os.system('python setup.py sdist bdist_wheel')
    sys.exit(0)

if sys.argv[-1] == 'install':
    os.system('python setup.py sdist --formats=zip')
    sys.exit(0)

setup(
    name='PyBurprestapi',
    packages=['PyBurprestapi'],
    version=version,
    description='Python library enumerating the Burp RESTFul API endpoints.',
    long_description=readme,
    author='Anand Tiwari',
    author_email='anandtiwarics@gmail.com',
    url='https://github.com/anandtiwarics/python-burp-rest-api/',
    download_url='https://github.com/anandtiwarics/python-burp-rest-api/releases/download/v0.0.1/burprestapi-0.0.1.tar.gz',
    license='MIT License',
    zip_safe=True,
    install_requires=['requests'],
    keywords=['PyBurprestapi', 'api', 'security', 'software', 'burp'],
    classifiers=[
        'Intended Audience :: Developers',
        'Natural Language :: English',
        'License :: OSI Approved :: MIT License',
        'Topic :: Software Development',
        'Topic :: Software Development :: Libraries :: Python Modules',
        'Programming Language :: Python',
    ]
)
