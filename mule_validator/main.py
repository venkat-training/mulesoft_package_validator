"""
Main entry point for the MuleSoft Package Validator CLI tool.
This script orchestrates the validation of a MuleSoft package by invoking various
validators for dependencies, flows, API specifications, YAML configurations,
MuleSoft code review, logging practices, and component structure.

It serves as the command-line interface (CLI) for the MuleSoft Package Validator.
The script handles argument parsing, invokes Maven for project build, calls
individual validator modules, aggregates results, and generates an HTML report.
"""
import argparse
import subprocess
import logging
import sys
import os
import datetime
from tabulate import tabulate
from .dependency_validator import validate_all_projects
from .flow_validator import validate_flows_in_package
from .code_reviewer import review_all_files
from .api_validator import validate_api_spec_and_flows
from .configfile_validator import validate_files
from .logs_reviewer import validate_logging
from .html_reporter import generate_html_report

def get_current_git_branch(repo_path):
    """
    Returns the current git branch name for the Git repository at the given path.

    Uses `subprocess.run` to execute `git rev-parse --abbrev-ref HEAD`.
    If the command fails (e.g., not a git repository, git not installed, timeout)
    or if any exception occurs, it returns "Unknown".

    Args:
        repo_path (str): The file system path to the root of the Git repository.

    Returns:
        str: The current Git branch name, or "Unknown" if it cannot be determined.
    """
    try:
        result = subprocess.run(
            ["git", "rev-parse", "--abbrev-ref", "HEAD"],
            cwd=repo_path, # Execute in the context of the specified repository
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,      # Capture output as text
            check=False,    # Do not raise exception for non-zero exit codes directly
            timeout=5       # Set a timeout for the git command
        )
        if result.returncode == 0:
            return result.stdout.strip()
        else:
            logger.warning(f"Failed to get Git branch for {repo_path}. Error: {result.stderr.strip()}")
            return "Unknown"
    except FileNotFoundError:
        logger.error("Git command not found. Ensure Git is installed and in PATH.")
        return "Unknown"
    except subprocess.TimeoutExpired:
        logger.warning(f"Git command timed out for {repo_path}.")
        return "Unknown"
    except Exception as e:
        logger.error(f"An error occurred while getting Git branch for {repo_path}: {e}")
        return "Unknown"

def ensure_maven_and_build(project_dir: str) -> None:
    """
    Ensures Maven is available and successfully runs `mvn clean install -DskipTests`
    on the specified MuleSoft project directory before proceeding with validation.

    It first checks if 'mvn -v' can be executed. If Maven is not found,
    it prints an error message and exits the script with status code 1.
    Then, it attempts to build the project using `mvn clean install -DskipTests`.
    If the build fails, it prints the Maven output and exits with status code 1.

    This function is critical as some validations (like dependency checks and
    API spec presence in target) rely on a successful build.

    Args:
        project_dir (str): The root directory of the MuleSoft project.

    Raises:
        SystemExit: If Maven is not available or if the Maven build fails.
    """
    try:
        # Check for Maven availability
        result_mvn_version = subprocess.run(
            ["mvn", "-v"],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            shell=True, # shell=True might be needed if mvn is an alias or complex command
            check=False, # We handle the return code manually
            text=True
        )
        if result_mvn_version.returncode != 0:
            print("ERROR: Maven is not available or not found in PATH. Please install Maven and ensure it's in your PATH.")
            logger.error(f"Maven version check failed. Output: {result_mvn_version.stdout} Error: {result_mvn_version.stderr}")
            sys.exit(1) # Exit if Maven not found
    except FileNotFoundError:
        print("ERROR: Maven command 'mvn' not found. Please ensure Maven is installed and in your PATH.")
        logger.error("Maven command 'mvn' not found during version check.")
        sys.exit(1)
    except Exception as e:
        print(f"ERROR: An unexpected error occurred while checking for Maven: {e}")
        logger.error(f"Unexpected error during Maven version check: {e}")
        sys.exit(1)

    logger.info(f"Running 'mvn clean install -DskipTests' in directory: {project_dir}")
    try:
        build_process = subprocess.run(
            ["mvn", "clean", "install", "-DskipTests"],
            cwd=project_dir,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            shell=True, # Consider if shell=True is strictly necessary
            check=False, # We handle the return code manually
            text=True
        )
        if build_process.returncode != 0:
            print("\nERROR: Maven build failed. Validation cannot proceed.")
            print("Maven stdout:\n", build_process.stdout)
            print("Maven stderr:\n", build_process.stderr)
            logger.error(f"Maven build failed with return code {build_process.returncode}.")
            sys.exit(1)
        logger.info("Maven build successful. Proceeding with validation.")
        # Optionally print some output from successful build if needed for diagnostics
        # print("Maven build stdout (summary):\n", build_process.stdout[-500:]) # Last 500 chars
    except FileNotFoundError:
        print("ERROR: Maven command 'mvn' not found for build. Please ensure Maven is installed and in your PATH.")
        logger.error("Maven command 'mvn' not found during build execution.")
        sys.exit(1)
    except Exception as e:
        print(f"ERROR: An unexpected error occurred during Maven build: {e}")
        logger.error(f"Unexpected error during Maven build: {e}")
        sys.exit(1)


def main() -> None:
    """
    Main function to parse command-line arguments and orchestrate the validation
    of a MuleSoft package.

    The script performs the following steps:
    1.  Parses command-line arguments for package path, report file path (optional),
        build folder path (optional), and various validation thresholds.
    2.  Configures basic logging.
    3.  Calls `ensure_maven_and_build()` to verify Maven installation and build the project.
        The script exits if Maven is not found or the build fails.
    4.  Invokes various validation modules in sequence:
        - `code_reviewer.review_all_files()` (also determines secure properties usage)
        - `configfile_validator.validate_files()`
        - `dependency_validator.validate_all_projects()`
        - `flow_validator.validate_flows_in_package()`
        - `api_validator.validate_api_spec_and_flows()`
        - `logs_reviewer.validate_logging()`
    5.  Retrieves the current Git branch name.
    6.  Aggregates all results into a comprehensive dictionary.
    7.  Prints a summary of results to the console (currently prints the whole dict).
    8.  If a report file path is provided via `--report-file`, it generates an HTML
        report using `html_reporter.generate_html_report()` with a template file
        expected at `mule_validator/report_template.html`.

    The script uses `sys.exit(1)` to terminate if critical prerequisites (like Maven
    or a successful build) are not met.
    """
    start_time = datetime.datetime.now()
    # Configure Logging (basic configuration)
    logging.basicConfig(
        level=logging.INFO,
        format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
        handlers=[logging.StreamHandler(sys.stdout)] # Ensure logs go to stdout
    )
    logger = logging.getLogger(__name__)

    parser = argparse.ArgumentParser(
        description='Validate a MuleSoft package, checking API specifications, definition flows, YAML configurations, and more.'
    )
    parser.add_argument(
        'package_folder_path',
        type=str,
        help='The path to the MuleSoft package folder to validate.'
    )
    parser.add_argument(
        '--report-file',
        type=str,
        help='Optional. The path to save the HTML validation report.'
    )
    parser.add_argument(
        '--build-folder-path',
        type=str,
        default=None,
        help='The path to the MuleSoft build folder (e.g., containing the target JAR/ZIP). If not provided, defaults to the package_folder_path.'
    )
    threshold_group = parser.add_argument_group('Validation Thresholds')
    threshold_group.add_argument('--max-build-size-mb', type=int, default=100, help='Maximum allowed build size in MB. Default: 100')
    threshold_group.add_argument('--max-flows', type=int, default=100, help='Maximum allowed number of flows. Default: 100')
    threshold_group.add_argument('--max-sub-flows', type=int, default=50, help='Maximum allowed number of sub-flows. Default: 50')
    threshold_group.add_argument('--max-components', type=int, default=500, help='Maximum allowed number of components in flows/sub-flows. Default: 500')

    args = parser.parse_args()

    package_folder_path = args.package_folder_path
    build_folder_path = args.build_folder_path if args.build_folder_path else package_folder_path

    logger.info(f"Starting MuleSoft package validation for: {package_folder_path}")
    if args.build_folder_path:
        logger.info(f"Using custom build folder path: {build_folder_path}")
    else:
        logger.info(f"Build folder path not provided, defaulting to package folder path: {build_folder_path}")

    # Ensure Maven is available and build the project before validation
    ensure_maven_and_build(package_folder_path)

    # Step 1: Code Review (needed for secure properties info)
    logger.info("Reviewing flows and code structure...")
    code_reviewer_results, project_uses_secure_properties = review_all_files(package_folder_path)
    logger.info(f"Project uses Mule Secure Properties: {project_uses_secure_properties}")

    # Step 2: Validate YAML Files
    logger.info("Validating YAML configuration files...")
    yaml_validation_results = validate_files(package_folder_path, project_uses_secure_properties)

    # Step 3: Validate Dependencies
    logger.info("Validating dependencies and build size...")
    dependency_validation_results = validate_all_projects(package_folder_path)

    # Step 4: Validate Flows and Components
    logger.info("Validating flows and components...")
    flow_validation_results = validate_flows_in_package(
        package_folder_path,
        max_flows=args.max_flows,
        max_sub_flows=args.max_sub_flows,
        max_components=args.max_components
    )

    # Step 5: Validate API Specifications
    logger.info("Validating API specifications and definition flows...")
    api_validation_results = validate_api_spec_and_flows(package_folder_path)

    # Step 6: Logging validation (logger and log4j checks)
    logger.info("Starting logging validation (logger and log4j checks)...")
    logging_validation_results = validate_logging(package_folder_path)

    # Step 7: Get the current git branch name for reporting purposes
    logger.info("Retrieving current git branch name...")
    git_branch_name = get_current_git_branch(package_folder_path)

    end_time = datetime.datetime.now()
    duration = end_time - start_time

    # Combine all validation results into a single dictionary for a comprehensive summary.
    logger.info("All validations completed. Results collected.")
    all_results = {
        'yaml_validation': yaml_validation_results,
        'dependency_validation': dependency_validation_results,
        'flow_validation': flow_validation_results,
        'api_validation': api_validation_results,
        'code_reviewer_issues': code_reviewer_results,
        'project_uses_secure_properties': project_uses_secure_properties,
        'logging_validation': logging_validation_results,
        'git_branch_name': git_branch_name,
        'report_start_time': start_time.strftime('%Y-%m-%d %H:%M:%S'),
        'report_end_time': end_time.strftime('%Y-%m-%d %H:%M:%S'),
        'report_duration': str(duration)
    }

    # Print summary to console (optional)
    print("\nSummary of all validation results:", all_results)

    # Generate HTML report if the --report-file argument is provided
    if args.report_file:
        try:
            with open('mule_validator/report_template.html', 'r') as f_template:
                template_content = f_template.read()
            report_content = generate_html_report(all_results, template_content)
            with open(args.report_file, 'w') as f_report:
                f_report.write(report_content)
            print(f"\nHTML report generated successfully at: {args.report_file}")
        except FileNotFoundError:
            print(f"\nError: HTML template file not found at mule_validator/report_template.html. Report not generated.")
        except Exception as e:
            print(f"\nError generating HTML report: {e}")

if __name__ == '__main__':
    main()