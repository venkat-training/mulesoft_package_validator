# Mule Package Validator

This Python utility validates a MuleSoft package for dependency management, flow/component count, API specifications, configuration files, code quality, and logging practices.

## Features

-   **Dependency Validation**:
    *   Checks for unused dependencies by comparing `pom.xml` entries against their usage in Mule configuration files.
    *   Verifies build size against configurable limits (relevant for environments like MuleSoft CloudHub).
    *   Scans `pom.xml` files for hardcoded secrets or sensitive information within properties, plugin configurations, etc.

-   **Flow Validation**:
    *   Validates the number of flows, sub-flows, and components in the MuleSoft package against configurable thresholds.
    *   Implements enhanced flow name validation, including camel case checks with specific rules (e.g., handling of HTTP verb prefixes, APIkit-style suffixes, quoted names, backslashes), ignoring certain common substrings (e.g., "-main", "-console"), and correctly identifying common MIME types as valid names.

-   **Configuration File Validation (YAML)**:
    *   Checks YAML configuration files (e.g., `config-prod.yaml`, `config-nonprod.yaml`) for syntax validity.
    *   Scans for plaintext secrets using keyword and pattern matching.
    *   Compares environment-specific configuration files (e.g., prod vs. nonprod) to detect keys that are expected to differ (hostnames, IPs, passwords, URLs, etc.) but have identical values.
    *   Reduces false positives for secret detection by recognizing filename/path contexts for certain keys.

-   **API Validation**:
    *   Verifies that API specifications (e.g., RAML, OpenAPI) are correctly included as Maven dependencies in `pom.xml`.
    *   Ensures the API specification artifact (e.g., RAML ZIP) is present in the `target/` directory after a build.
    *   Checks for the presence of APIkit router configurations within the main Mule application XML file.

-   **Code Review**:
    *   Performs various checks on Mule XML configuration files:
        *   **Flow Naming Conventions**: Validates flow names based on the rules described in "Flow Validation".
        *   **Component Configurations**: Ensures common components (e.g., HTTP Listeners, Loggers, DataWeave transformations, HTTP Requesters, various connectors) have essential attributes defined (e.g., HTTP Listener `path`, Logger `message`, Requester `url`).
    *   **MuleSoft Secure Property Awareness**:
        *   Automatically detects if the project uses MuleSoft's standard secure properties (`<secure-properties:config>`).
        *   Adjusts YAML content validation based on this:
            *   Encrypted values (`![...]`) in YAML are not flagged as plaintext secrets if secure properties are enabled project-wide (otherwise, a warning is issued about using encryption without configuration).
            *   Provides more relevant feedback for sensitive keywords in YAML if values are not encrypted but secure properties are available.

-   **Logs Validation**:
    *   Checks Mule XML files for logger component best practices:
        *   Flags flows with an excessive number of `<logger>` components.
        *   Identifies usage of "DEBUG" level loggers.
        *   Warns about "ERROR" level loggers found outside of recognized error handler scopes (based on a heuristic check of parent elements).
    *   Analyzes `log4j2.xml` for risky root logger configurations (e.g., DEBUG, TRACE, INFO levels in production configurations).

-   **HTML Report Generation**:
    *   Optionally generates a comprehensive HTML report of all validation results.
    *   The report includes the Git branch name (if available) from which the validation was run, and timing information (start, end, duration).
    *   Standard console output remains available.

## Installation

Clone this repository and navigate to the project directory:

```bash
git clone https://github.com/your-repo/mule_package_validator.git # Replace with your actual repository URL
cd mule_package_validator
pip install -e .
```
This installs the package in editable mode. Python will be able to find the `mule_validator` modules.

*Note: If you encounter installation issues, you might need to upgrade pip and setuptools (`pip install --upgrade pip setuptools`) or, in some environments, try `pip install -e . --use-pep517`.*

## Using `main.py` for Comprehensive Validation

The `mule_validator/main.py` script is the primary entry point to run all available validations on your MuleSoft package. It requires Maven to be installed and accessible in your system's PATH to perform a build (`mvn clean install -DskipTests`) before validation.

**Basic Usage:**

Navigate to the cloned `mule_package_validator` directory (or ensure it's in your PYTHONPATH) and run:

```bash
python -m mule_validator.main /path/to/your/mulesoft/project
```
*(Using `python -m mule_validator.main` is a robust way to invoke the main module after installation.)*

This will run all validations and print the results to the console.

**Command-Line Arguments:**

The `main.py` script accepts several command-line arguments to customize its behavior:

*   `package_folder_path`: (Required) The file system path to the root of the MuleSoft project to validate.
*   `--report-file REPORT_FILE`: (Optional) The path to save the HTML validation report. If provided, an HTML report will be generated.
    *   Example: `--report-file validation_report.html`
*   `--build-folder-path BUILD_FOLDER_PATH`: (Optional) The path to the MuleSoft build folder (e.g., the directory containing the `target/` directory, typically the same as `package_folder_path`). If not provided, it defaults to `package_folder_path`.
*   `--max-build-size-mb MAX_BUILD_SIZE_MB`: (Optional) Maximum allowed build size in MB for the `target` directory.
    *   Default: `100` MB. (Note: This check is currently illustrative as `dependency_validator.calculate_build_size` is not directly integrated into `main.py`'s threshold reporting yet.)
*   `--max-flows MAX_FLOWS`: (Optional) Maximum allowed total number of flows in the package.
    *   Default: `100`.
*   `--max-sub-flows MAX_SUB_FLOWS`: (Optional) Maximum allowed total number of sub-flows in the package.
    *   Default: `50`.
*   `--max-components MAX_COMPONENTS`: (Optional) Maximum allowed total number of components within all flows and sub-flows.
    *   Default: `500`.

**Example with HTML Report and Custom Thresholds:**

```bash
python -m mule_validator.main /path/to/your/mulesoft/project --report-file report.html --max-flows 120 --max-components 600
```
This will execute all validations with custom thresholds for flows and components, print results to the console, and save a detailed HTML report to `report.html`.

## Contributing
Pull requests are welcome. For major changes, please open an issue first to discuss what you would like to change.

Please make sure to update tests as appropriate.

## License
[MIT](https://choosealicense.com/licenses/mit/)
