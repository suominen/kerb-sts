"""
The setup module for the CommerceHub implementation of Kerberos=>AWSRole Simple
Token Service authentication.
"""

# Always prefer setuptools over distutils
from setuptools import setup, find_packages
# To use a consistent encoding
from codecs import open
from os import path, environ

#
# Setup version information from environment variables. They are set in
# the build environment.
#
MAJOR_VERSION = 0
MINOR_VERSION = 0
BUILD_NUMBER = 0

if 'MAJOR_VERSION' in environ:
    MAJOR_VERSION = environ['MAJOR_VERSION']

if 'MINOR_VERSION' in environ:
    MINOR_VERSION = environ['MINOR_VERSION']

if 'BUILD_NUMBER' in environ:
    BUILD_NUMBER = environ['BUILD_NUMBER']

VERSION = '{0}.{1}.{2}'.format(MAJOR_VERSION, MINOR_VERSION, BUILD_NUMBER)

here = path.abspath(path.dirname(__file__))

# Get the long description from the README file
with open(path.join(here, 'README.md'), encoding='utf-8') as f:
    long_description = f.read()

setup(
    name='kerb-sts',
    version=VERSION,

    description='Renew AWS Simple Token Service Credentials',
    long_description=long_description,

    url='https://github.com/commercehub-oss/kerb-sts.git',
    author='CommerceHub',

    packages=find_packages(),

    classifiers=[
        'Programming Language :: Python :: 2.7',
        'Programming Language :: Python :: 3.4',
        'Programming Language :: Python :: 3.5',
    ],
    install_requires=[
        'beautifulsoup4>=4.4.1',
        'boto>=2.39.0',
        'requests-ntlm>=0.2.0',
        'requests-kerberos>=0.8.0',
        'configparser==3.5.0b2'
    ],
    
    entry_points={
        'console_scripts': [
            'kerb-sts=kerb_sts.__main__:main'
        ]
    }
)
