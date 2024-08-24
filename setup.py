from setuptools import setup, find_packages

setup(
    name="mule_package_validator",
    version="1.0.0",
    packages=find_packages(),
    install_requires=[
        # List your package dependencies here
    ],
    entry_points={
        'console_scripts': [
            # Define command-line scripts here if needed
        ],
    },
)
