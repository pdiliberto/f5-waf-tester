#!/usr/bin/env python

import re
from os import path
from setuptools import setup, find_packages

__folder__ = path.abspath(path.dirname(__file__))


def get_readme():
    with open(path.join(__folder__, 'README.md')) as ld_file:
        long_description = ld_file.read()
        return long_description


def get_version():
    with open(path.join(__folder__, 'f5_waf_tester', '__init__.py')) as lib_file:
        r = re.search(r'__version__\s*=\s*(?P<q>["\']+)(?P<ver>[^(?P=q)]+)(?P=q)', lib_file.read())
        return r.group('ver')


setup(
    name='f5-waf-tester',
    version=get_version(),
    description='Web Application Firewall Security Testing Tool',
    long_description=get_readme(),
    author='RealGame (Tomer Zait)',
    author_email='realgam3@gmail.com',
    packages=find_packages(exclude=['examples', 'tests', 'config']),
    package_data={
        '': ['config/tests.json']
    },
    py_modules=['f5_waf_tester'],
    entry_points={
        'console_scripts': [
            'f5-waf-tester = f5_waf_tester:main',
        ]
    },
    install_requires=[
        'requests >= 2.11.1',
    ],
    license="Apache-2.0",
    platforms='any',
    url='https://github.com/f5devcentral/f5-waf-tester',
    classifiers=[
        'License :: OSI Approved :: Apache Software License',
        'Development Status :: 4 - Beta',
        'Environment :: Console',
        'Natural Language :: English',
        'Intended Audience :: Developers',
        'Intended Audience :: Science/Research',
        'Operating System :: POSIX :: Linux',
        'Operating System :: MacOS :: MacOS X',
        'Operating System :: Microsoft :: Windows',
        'Programming Language :: Python :: 2',
        'Programming Language :: Python :: 3',
        'Topic :: Security',
        'Topic :: Internet',
        'Topic :: Internet :: WWW/HTTP',
        'Topic :: Software Development :: Testing',
        'Topic :: Software Development :: Libraries :: Python Modules'
    ]
)
