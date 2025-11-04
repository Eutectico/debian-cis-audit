#!/usr/bin/env python3
"""
Setup script for Debian CIS Audit
"""

from setuptools import setup, find_packages
from pathlib import Path

# Read the long description from README
this_directory = Path(__file__).parent
long_description = (this_directory / "README.md").read_text(encoding='utf-8')

setup(
    name='debian-cis-audit',
    version='1.0.0',
    description='Debian CIS Benchmark Audit Script - Security and compliance auditing tool',
    long_description=long_description,
    long_description_content_type='text/markdown',
    author='Debian CIS Audit Contributors',
    author_email='',
    url='https://github.com/Eutectico/debian-cis-audit',
    license='MIT',

    # Package configuration
    py_modules=['debian_cis_audit', 'test_auditd_check', 'monitoring_integration_example'],
    python_requires='>=3.6',

    # No external dependencies - uses only Python standard library
    install_requires=[],

    # Development dependencies
    extras_require={
        'dev': [
            'pylint>=2.17.0',
            'flake8>=6.0.0',
            'black>=23.0.0',
            'mypy>=1.0.0',
            'pytest>=7.3.0',
            'pytest-cov>=4.0.0',
        ],
    },

    # Entry points for command-line scripts
    entry_points={
        'console_scripts': [
            'debian-cis-audit=debian_cis_audit:main',
            'debian-cis-monitor=monitoring_integration_example:main',
        ],
    },

    # Classifiers for PyPI
    classifiers=[
        'Development Status :: 4 - Beta',
        'Intended Audience :: System Administrators',
        'Intended Audience :: Information Technology',
        'License :: OSI Approved :: MIT License',
        'Operating System :: POSIX :: Linux',
        'Programming Language :: Python :: 3',
        'Programming Language :: Python :: 3.6',
        'Programming Language :: Python :: 3.7',
        'Programming Language :: Python :: 3.8',
        'Programming Language :: Python :: 3.9',
        'Programming Language :: Python :: 3.10',
        'Programming Language :: Python :: 3.11',
        'Programming Language :: Python :: 3.12',
        'Topic :: Security',
        'Topic :: System :: Systems Administration',
        'Topic :: System :: Monitoring',
    ],

    # Keywords for PyPI search
    keywords='security audit cis benchmark debian compliance hardening',

    # Project URLs
    project_urls={
        'Bug Reports': 'https://github.com/Eutectico/debian-cis-audit/issues',
        'Source': 'https://github.com/Eutectico/debian-cis-audit',
        'Documentation': 'https://github.com/Eutectico/debian-cis-audit#readme',
        'Funding': 'https://www.buymeacoffee.com/Eutectico',
    },
)
