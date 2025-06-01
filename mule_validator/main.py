import argparse
import logging
import subprocess
import sys
import os
from .reporter import generate_console_report
from .dependency_validator import validate_all_projects  # Use the advanced dependency validator
from .flow_validator import validate_flows_in_package
from .code_reviewer import review_all_files
from .api_validator import validate_api_spec_and_flows
from .configfile_validator import validate_files

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
    Main function to parse command-line arguments and validate the MuleSoft package.
    Performs the following validations:
    1. YAML configuration file validation
    2. Dependency validation (checks all pom.xml files for missing/unresolved/duplicate dependencies)
    3. Flow and component validation
    4. API specification and definition flow validation
    5. Code review of flow definitions
    Results are aggregated and reported via the configured reporter.
    """
    # Configure Logging
    logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(name)s - %(levelname)s - %(message)s')
    logger = logging.getLogger(__name__)

    # Create the parser
    parser = argparse.ArgumentParser(description='Validate MuleSoft package for API specifications and definition flows.')

    # Add the package folder path argument
    parser.add_argument(
        'package_folder_path',
        type=str,
        help='The path to the MuleSoft package folder to validate.'
    )
    # Add the build folder path argument
    parser.add_argument(
        '--build-folder-path',
        type=str,
        default=None,
        help='The path to the MuleSoft build folder (e.g., containing the target JAR/ZIP). '
             'If not provided, defaults to the package_folder_path.'
    )

    # Add validation thresholds argument group
    threshold_group = parser.add_argument_group('Validation Thresholds')
    threshold_group.add_argument(
        '--max-build-size-mb',
        type=int,
        default=100,
        help='Maximum allowed build size in MB. Default: 100'
    )
    threshold_group.add_argument(
        '--max-flows',
        type=int,
        default=100,
        help='Maximum allowed number of flows. Default: 100'
    )
    threshold_group.add_argument(
        '--max-sub-flows',
        type=int,
        default=50,
        help='Maximum allowed number of sub-flows. Default: 50'
    )
    threshold_group.add_argument(
        '--max-components',
        type=int,
        default=500,
        help='Maximum allowed number of components in flows/sub-flows. Default: 500'
    )

    # Parse the command-line arguments
    args = parser.parse_args()

    # Define the paths to your MuleSoft package and build folder
    package_folder_path = args.package_folder_path
    build_folder_path = args.build_folder_path if args.build_folder_path else args.package_folder_path

    logger.info(f"Starting MuleSoft package validation for: {package_folder_path}")
    if args.build_folder_path:
        logger.info(f"Using custom build folder path: {build_folder_path}")
    else:
        logger.info(f"Build folder path not provided, defaulting to package folder path: {build_folder_path}")

    # Ensure Maven is available and build the project before validation
    ensure_maven_and_build(package_folder_path)

    # 1. Validate YAML Files
    logger.info("Starting YAML configuration file validation...")
    yaml_validation_results = validate_files(package_folder_path)

    # 2. Validate Dependencies (advanced: checks all pom.xml files in the project tree)
    logger.info("Starting dependency validation for all Maven projects...")
    dependency_validation_results = validate_all_projects(package_folder_path)

    # 3. Validate Flows and Components
    logger.info("Starting flow and component validation...")
    flow_validation_results = validate_flows_in_package(
        package_folder_path,
        max_flows=args.max_flows,
        max_sub_flows=args.max_sub_flows,
        max_components=args.max_components
    )

    # 4. Validate API Specifications and Definition Flows
    logger.info("Starting API specification and definition flow validation...")
    api_validation_results = validate_api_spec_and_flows(package_folder_path)
    
    # 5. Code Review the flow definitions
    logger.info("Starting code review of flow definitions...")
    code_reviewer_results = review_all_files(package_folder_path)

    # Combine all results
    logger.info("All validations completed. Results collected.")
    all_results = {
        'yaml_validation': yaml_validation_results,
        'dependency_validation': dependency_validation_results,
        'flow_validation': flow_validation_results,
        'api_validation': api_validation_results,
        'code_reviewer' : code_reviewer_results
    }
    
    generate_console_report(all_results)

if __name__ == '__main__':
    main()