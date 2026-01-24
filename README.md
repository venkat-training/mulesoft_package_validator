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

-   **Orphan Component Detection**:
    *   Identifies unused (orphaned) components in MuleSoft applications including:
        *   Flows and sub-flows that are declared but never referenced
        *   Configuration objects that are defined but not used
        *   Variables that are set but never accessed
        *   Property keys from YAML files that are declared but not referenced
        *   Error handlers and exception strategies that are unused
        *   HTTP endpoints and DataWeave scripts that are orphaned
    *   Automatically excludes APIKit-generated flows and externally triggered flows (with schedulers/listeners)
    *   Generates detailed HTML reports showing orphaned vs. used components with file locations

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

## Batch Processing Scripts

For processing multiple MuleSoft projects at once, the repository includes batch processing scripts that automatically scan all projects in a directory and generate individual reports for each project.

### PowerShell Script (Windows)

The `scan_all_projects.ps1` script provides batch processing capabilities for Windows environments.

**Usage:**
```powershell
# Show help
.\scan_all_projects.ps1 -Help

# Basic usage - scan all projects in a directory
.\scan_all_projects.ps1 -ProjectsDirectory "C:\Projects\MuleSoft"

# With custom report directory
.\scan_all_projects.ps1 -ProjectsDirectory "C:\Projects\MuleSoft" -ReportDirectory "C:\Reports"

# With specific Python path (if auto-detection fails)
.\scan_all_projects.ps1 -ProjectsDirectory "C:\Projects\MuleSoft" -PythonPath "C:\Python\python.exe"
```

**Parameters:**
- `-ProjectsDirectory` (Required): Base directory containing MuleSoft project repositories
- `-ReportDirectory` (Optional): Directory to store HTML reports (default: `./reports`)
- `-PythonPath` (Optional): Path to Python executable (auto-detected if not specified)
- `-Help`: Show help information

**Features:**
- Automatic Python detection across common installation paths
- Colored output for better readability
- Progress tracking with success/failure counts
- Comprehensive error handling and validation
- Automatic report directory creation

### Shell Script (Linux/macOS/WSL)

The `scan_all_projects.sh` script provides batch processing capabilities for Unix-like environments.

**Usage:**
```bash
# Show help
./scan_all_projects.sh -h

# Basic usage - scan all projects in a directory
./scan_all_projects.sh -d "/home/user/projects/mulesoft"

# With custom report directory
./scan_all_projects.sh -d "/home/user/projects/mulesoft" -r "/home/user/reports"

# With specific Python path (if auto-detection fails)
./scan_all_projects.sh -d "/home/user/projects/mulesoft" -p "/usr/bin/python3"
```

**Parameters:**
- `-d, --projects-dir` (Required): Base directory containing MuleSoft project repositories
- `-r, --report-dir` (Optional): Directory to store HTML reports (default: `./reports`)
- `-p, --python-path` (Optional): Path to Python executable (auto-detected if not specified)
- `-h, --help`: Show help information

**Features:**
- Cross-platform compatibility (Linux, macOS, WSL)
- Colored terminal output with visual indicators
- Automatic Python detection across system paths
- Robust error handling with detailed feedback
- Summary statistics upon completion

### Script Output

Both scripts provide:
- **Real-time progress**: Shows which project is currently being processed
- **Visual feedback**: Color-coded success/failure indicators
- **Summary statistics**: Total successful and failed validations
- **Individual reports**: Separate HTML report for each project
- **Error details**: Clear error messages for troubleshooting

### Integration with CI/CD

The scripts can be easily integrated into CI/CD pipelines:

```yaml
# Example GitHub Actions workflow
- name: Validate MuleSoft Projects
  run: |
    ./scan_all_projects.sh -d "${{ github.workspace }}/mulesoft-projects" -r "${{ github.workspace }}/reports"
```

```powershell
# Example Azure DevOps PowerShell task
.\scan_all_projects.ps1 -ProjectsDirectory "$(Build.SourcesDirectory)\mulesoft-projects" -ReportDirectory "$(Build.ArtifactStagingDirectory)\reports"
```

## Individual Module Usage

You can also use individual validator modules directly:

### Orphan Checker
```bash
python -m mule_validator.mule_orphan_checker /path/to/mulesoft/project --html orphan_report.html
```

### Dependency Validator
```python
from mule_validator.dependency_validator import validate_all_projects
results = validate_all_projects("/path/to/project")
```

### Flow Validator
```python
from mule_validator.flow_validator import validate_flows_in_package
results = validate_flows_in_package("/path/to/project")
```

## Contributing
Pull requests are welcome. For major changes, please open an issue first to discuss what you would like to change.

Please make sure to update tests as appropriate.

## License
[MIT](https://choosealicense.com/licenses/mit/)
