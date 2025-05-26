from setuptools import setup, find_packages

setup(
    name="mule_package_validator",
    version="1.0.0",
    packages=find_packages(),
    install_requires=[
        "lxml",
        "PyYAML",
        "tabulate",
    ],
    entry_points={
        'console_scripts': [
            "mule-validator = mule_validator.main:main",
        ],
    },
)
