"""
Setup configuration for MuleSoft Package Validator
"""
from setuptools import setup, find_packages
from pathlib import Path

# Read long description from README
this_directory = Path(__file__).parent
long_description = (this_directory / "README.md").read_text(encoding='utf-8')

setup(
    name='mulesoft-package-validator',
    version='1.0.0',
    author='Venkat',
    author_email='venkiwm@gmail.com',
    description='Comprehensive validation tool for MuleSoft projects',
    long_description=long_description,
    long_description_content_type='text/markdown',
    url='https://github.com/venkat-training/mulesoft_package_validator',
    packages=find_packages(exclude=['tests', 'tests.*']),
    classifiers=[
        'Development Status :: 4 - Beta',
        'Intended Audience :: Developers',
        'Topic :: Software Development :: Quality Assurance',
        'License :: OSI Approved :: MIT License',
        'Programming Language :: Python :: 3',
        'Programming Language :: Python :: 3.8',
        'Programming Language :: Python :: 3.9',
        'Programming Language :: Python :: 3.10',
        'Programming Language :: Python :: 3.11',
        'Programming Language :: Python :: 3.12',
    ],
    python_requires='>=3.8',
    install_requires=[
        'lxml>=4.9.0',
        'tabulate>=0.9.0',
        'PyYAML>=6.0',
    ],
    extras_require={
        'dev': [
            'pytest>=7.0.0',
            'pytest-cov>=3.0.0',
            'black>=22.0.0',
            'flake8>=4.0.0',
            'mypy>=0.950',
        ],
    },
    entry_points={
        'console_scripts': [
            'mule-validator=mule_validator.main:main',
        ],
    },
    include_package_data=True,
    package_data={
        'mule_validator': ['report_template.html'],
    },
    project_urls={
        'Bug Reports': 'https://github.com/venkat-training/mulesoft_package_validator/issues',
        'Source': 'https://github.com/venkat-training/mulesoft_package_validator',
    },
    keywords='mulesoft validation testing quality-assurance security',
)