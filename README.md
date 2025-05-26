# Mule Package Validator (`mule-validator`)

## Overview

`mule-validator` is a Python command-line interface (CLI) tool designed to validate MuleSoft projects. It checks your project against a set of best practices, configurable thresholds for code metrics, and common code conventions to help ensure quality and consistency.

## Features

-   **Configuration Files**: Validates the presence and YAML syntax of standard configuration files (e.g., `config-prod.yaml`, `config-nonprod.yaml`) located in `src/main/resources`.
-   **Dependency Management**:
    -   Scans your `pom.xml` to identify declared dependencies.
    -   Checks for unused dependencies by looking for their usage within your Mule XML configuration files.
    -   Validates the overall build artifact size against a configurable limit (default: 100MB).
-   **Flow & Component Counts**:
    -   Counts the number of flows, sub-flows, and components within these flows in your Mule XML files (`src/main/mule`).
    -   Validates these counts against configurable limits.
-   **API Specifications**:
    -   Ensures the presence of API specification files (RAML, YAML, or JSON) in the `src/main/resources/api` directory.
-   **API Implementation**:
    -   Checks for the presence of API implementation flows (conventionally named containing "api") within your Mule XML files in `src/main/mule`.
-   **Code Review**:
    -   Performs static analysis on Mule XML configuration files found in `src/main/mule`.
    -   Checks for common issues and adherence to naming conventions, such as:
        -   Flow naming (camelCase, valid characters).
        -   Presence of critical attributes in components like HTTP Listeners (`path`), Loggers (`message`), DataWeave transforms (`dw:set-payload`), Schedulers, and various connector configurations.
-   **Configurable Thresholds**: Many validation aspects, such as build size, flow counts, and component counts, can be customized using CLI arguments.

## Installation

### Prerequisites

-   Python 3.6 or higher.

### Steps

1.  Clone this repository (if you haven't already) or ensure you have access to the project's root directory.
2.  Navigate to the root directory of the `mule-validator` project.
3.  Install the tool using pip:

    ```bash
    pip install .
    ```

    This will install the package and make the `mule-validator` command available in your environment.

4.  For development purposes (e.g., if you are making changes to the validator itself), install it in editable mode:

    ```bash
    pip install -e .
    ```

## Usage

Once installed, `mule-validator` can be run from your terminal.

### Command-Line Interface

```bash
mule-validator <package_folder_path> [options]
```

### Arguments and Options

-   **`package_folder_path`**: (Positional, Mandatory)
    -   The full path to the root directory of the MuleSoft project you want to validate.

-   **`--build-folder-path <path>`**: (Optional)
    -   Path to the build folder (e.g., where the `target` directory containing the deployable archive is located).
    -   This path is used for build size validation.
    -   If not provided, it defaults to the `package_folder_path`.

-   **`--max-build-size-mb <size>`**: (Optional)
    -   Maximum allowed build artifact size in Megabytes (MB).
    -   *Default*: `100`

-   **`--max-flows <count>`**: (Optional)
    -   Maximum allowed number of flows in the project.
    -   *Default*: `100`

-   **`--max-sub-flows <count>`**: (Optional)
    -   Maximum allowed number of sub-flows in the project.
    -   *Default*: `50`

-   **`--max-components <count>`**: (Optional)
    -   Maximum allowed number of components within flows and sub-flows.
    -   *Default*: `500`

### Example Command

```bash
mule-validator /path/to/your/mulesoft-project --max-flows 150 --build-folder-path /path/to/your/mulesoft-project/target
```

## Output Interpretation

The `mule-validator` tool outputs a formatted report directly to the console. The report is divided into sections, each corresponding to a major validation category (e.g., YAML VALIDATION, DEPENDENCY VALIDATION, FLOW VALIDATION, etc.).

Each section will:
-   Summarize the findings for that category.
-   List specific issues, errors, or details discovered during the validation. For example, missing mandatory configuration files, unused dependencies, flows exceeding component limits, or specific code review violations per file.
-   Use tables for structured data where appropriate (e.g., YAML file status, flow counts).

Review the output carefully to identify areas in your MuleSoft project that may need attention.

## Validations Performed (Detailed Summary)

-   **YAML Configuration Files (`configfile_validator`)**:
    -   Checks the `src/main/resources/` directory.
    -   **Mandatory**: `config-prod.yaml`, `config-nonprod.yaml`. Reports if missing or invalid YAML.
    -   **Optional**: `config-dev.yaml`, `config-uat.yaml`, `config-local.yaml`. Reports if invalid YAML (if present).
    -   Validates the YAML syntax of all found configuration files.

-   **Dependency Management (`dependency_validator`)**:
    -   Parses `pom.xml` in the `package_folder_path` to extract declared dependencies.
    -   Scans Mule XML files within the project for string occurrences of dependency `groupId`s and `artifactId`s to identify used dependencies.
    -   Reports dependencies declared in `pom.xml` but not found in the code as "unused."
    -   Calculates the total size of the directory specified by `build_folder_path` (or `package_folder_path` if not specified) and compares it against the `max_build_size_mb` limit.

-   **Flow & Component Counts (`flow_validator`)**:
    -   Scans all Mule XML configuration files within the `src/main/mule/` directory.
    -   Counts the total number of `<flow>` elements.
    -   Counts the total number of `<sub-flow>` elements.
    -   Counts the total number of message processors (components) within each flow and sub-flow.
    -   Compares these counts against `max_flows`, `max_sub_flows`, and `max_components` limits.

-   **API Specifications (`api_validator`)**:
    -   Checks for the presence of API specification files (extensions: `.raml`, `.yaml`, `.json`) within the `src/main/resources/api/` directory.
    -   Reports if any specification files are found and lists them.

-   **API Implementation (`api_validator`)**:
    -   Scans Mule XML files in `src/main/mule/`.
    *   Identifies flows whose `name` attribute contains the substring "api" (case-insensitive) as potential API implementation flows.
    -   Reports if any such flows are found and lists the files containing them.

-   **Code Review (`code_reviewer`)**:
    -   Performs static analysis on Mule XML files in `src/main/mule/`.
    -   Excludes `pom.xml`, files in `target/` or `test/` directories, and files with `munit` in their name.
    -   Checks include, but are not limited to:
        -   **Flow Naming**: Ensures flow names are in camelCase (e.g., `mySampleFlow`) and use only alphanumeric characters.
        -   **HTTP Listener**: Path attribute should be defined.
        -   **Logger**: Message attribute should be defined.
        -   **DataWeave (Transform Message)**: Should contain a `<dw:set-payload>` element.
        -   **HTTP Response Builder**: Should define a status code.
        -   **Scheduler**: Critical attributes like frequency or cron expression should be present.
        -   **Connector Configurations**: Checks for presence of `config-ref` where expected (e.g., for various connectors like FTP, SFTP, SMTP) or essential attributes like URL for HTTP Requesters.

## Limitations

-   Dependency usage scanning is based on string matching of `artifactId` and `groupId` within XML files. This method is generally effective for common usage patterns but might not be 100% accurate in all complex scenarios or for dependencies used only in Java code or less common XML attributes.
-   Code review checks are based on a set of common conventions. These may need adjustment or may not perfectly align with all specific project guidelines or custom connector usage.

## Contributing

Contributions are welcome! Please refer to `CONTRIBUTING.md` (to be created) for guidelines on how to contribute, set up the development environment, run tests, and report issues.
