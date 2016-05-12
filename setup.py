"""
The setup module for the CommerceHub implementation of Kerberos=>AWSRole Simple
Token Service authentication.
"""

# Always prefer setuptools over distutils
from setuptools import setup, find_packages
# To use a consistent encoding
from codecs import open
from os import path, environ
import subprocess

try:
  version = subprocess.check_output(['git', 'describe', '--tags']).decode('utf-8').rstrip()
except:
  version = '0.0.0'

here = path.abspath(path.dirname(__file__))

# Get the long description from the README file
with open(path.join(here, 'README.md'), encoding='utf-8') as f:
    long_description = f.read()

setup(
    name='kerb-sts',
    version=version,

    description='Renew AWS Simple Token Service Credentials',
    long_description=long_description,

    url='https://github.com/commercehub-oss/kerb-sts.git',
    author='CommerceHub',

    packages=find_packages(),

    classifiers=[
        'Programming Language :: Python :: 2.7',
        'Programming Language :: Python :: 3.2',
        'Programming Language :: Python :: 3.3',
        'Programming Language :: Python :: 3.4',
        'Programming Language :: Python :: 3.5',
    ],
    install_requires=[
        'beautifulsoup4>=4.4.1',
        'boto>=2.39.0',
        'requests-ntlm>=0.2.0',
        'requests-kerberos==0.8.0',
        'configparser==3.5.0b2'
    ],
    
    entry_points={
        'console_scripts': [
            'kerb-sts=kerb_sts.__main__:main'
        ]
    }
)
