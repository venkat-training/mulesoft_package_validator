# Mule Package Validator

This Python utility validates a MuleSoft package for dependency management, flow/component count, and API specifications.

## Features

- **Dependency Validation**: Checks for unused dependencies and verifies build size against MuleSoft CloudHub deployment limits.
- **Flow Validation**: Validates the number of flows, sub-flows, and components in the MuleSoft package.
- **API Validation**: Ensures the presence of API specifications and API definition flows.

## Installation

Clone this repository and navigate to the project directory:

```bash
git clone https://github.com/your-repo/mule_package_validator.git
cd mule_package_validator

## To use the utility in your CI/CD pipeline, simply import the necessary module and call the function

from mule_validator.dependency_validator import validate_dependencies_and_size

package_folder_path = '/path/to/mulesoft/package'
build_folder_path = '/path/to/build/folder'

result = validate_dependencies_and_size(package_folder_path, build_folder_path)
print(result)

## setup main.py
On Unix or macOS, you can run:
export PYTHONPATH=.
python main.py

On Windows, you can run:
set PYTHONPATH=.
python main.py

You can also install your project as an editable package using pip. This allows Python to recognize the package without adjusting PYTHONPATH.

Navigate to your project directory and run:
pip install -e . --use-pep517

pip install -e .

pip install --upgrade setuptools
