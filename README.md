# Mule Package Validator

This Python utility validates a MuleSoft package for dependency management, flow/component count, and API specifications.

## Features

- **Dependency Validation**: Checks for unused dependencies and verifies build size against MuleSoft CloudHub deployment limits.
- **Flow Validation**: Validates the number of flows, sub-flows, and components in the MuleSoft package.
- **API Validation**: Ensures the presence of API specifications and API definition flows.

## MuleSoft Secure Property Awareness

The validator now includes features to intelligently handle MuleSoft's secure property configurations:

-   **Automatic Detection:** The validator automatically detects if your MuleSoft project is configured to use MuleSoft's standard secure properties by looking for the `<secure-properties:config ... />` element in your Mule XML configuration files.
-   **Smarter Validation:** When secure property usage is detected project-wide, the validator adjusts its behavior for certain checks in YAML configuration files to reduce false positives and provide more relevant feedback:
    -   **Generic Secret Patterns:** If a property value is encrypted using the MuleSoft format (e.g., `my.secret: "![encryptedValue]"`), the validator will not flag the encrypted content as a potential leaked secret. Instead, it will issue an informational message acknowledging that the value is encrypted.
    -   **Sensitive Keywords in Property Names:** If a property name contains sensitive keywords (like `password`, `apiKey`, `secret`, `token`), and its value is correctly encrypted in the `![...]` format, the validator will treat this appropriately, often issuing an informational message instead of a high-severity warning for plaintext exposure.
-   **Example Informational Messages:** With this feature, you might see messages like:
    -   `INFO: Key 'some.key.name' has Mule encrypted value. Length: XX.`
    -   `INFO: Key 'db.password' (sensitive keyword) has Mule encrypted value.` (This specific message format might vary slightly based on the exact check that identifies it, but the intent is to inform about secured sensitive keys).
-   **Benefit:** This enhancement makes the validator more accurate for projects that correctly implement MuleSoft's secure property mechanism. It helps distinguish between actual plaintext secrets and properly secured configurations, leading to more actionable validation results.

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
