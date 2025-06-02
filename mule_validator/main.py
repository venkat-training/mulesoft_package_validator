"""
Main entry point for the MuleSoft Package Validator CLI tool.
This script orchestrates the validation of a MuleSoft package by invoking various
validators for dependencies, flows, API specifications, YAML configurations,
MuleSoft code review, and component structure.
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
    Returns the current git branch name for the given repo path.
    """
    try:
        result = subprocess.run(
            ["git", "rev-parse", "--abbrev-ref", "HEAD"],
            cwd=repo_path,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            timeout=5
        )
        if result.returncode == 0:
            return result.stdout.strip()
        else:
            return "Unknown"
    except Exception:
        return "Unknown"

def ensure_maven_and_build(project_dir):
    """
    Ensures Maven is available and runs 'mvn clean install' before validation.
    Exits the process if Maven is not available or the build fails.
    """
    try:
        result = subprocess.run(["mvn", "-v"], stdout=subprocess.PIPE, stderr=subprocess.PIPE, shell=True)
        if result.returncode != 0:
            print("Maven is not available or not in PATH. Please install Maven and ensure it's in your PATH.")
            sys.exit(1)
    except Exception as e:
        print(f"Error checking Maven: {e}")
        sys.exit(1)

    print("Running 'mvn clean install' to build the project and resolve dependencies...")
    build = subprocess.run(
        ["mvn", "clean", "install", "-DskipTests"],
        cwd=project_dir,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        shell=True
    )
    if build.returncode != 0:
        print("Maven build failed. Validation cannot proceed.")
        print(build.stdout.decode())
        print(build.stderr.decode())
        sys.exit(1)
    print("Build successful. Proceeding with validation.")

def main():
    """
    Main function to parse command-line arguments and orchestrate the validation
    of a MuleSoft package.
    """
    start_time = datetime.datetime.now()
    # Configure Logging
    logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(name)s - %(levelname)s - %(message)s')
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