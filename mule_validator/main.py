import argparse
import logging # Added import
from .reporter import generate_console_report # Added import
from .dependency_validator import validate_dependencies_and_size
from .flow_validator import validate_flows_in_package
from .code_reviewer import review_all_files
from .api_validator import validate_api_spec_and_flows
from .configfile_validator import validate_files


def main():

    """
    Main function to parse command-line arguments and validate the MuleSoft package.
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

    #1. Validate YAML Files
    logger.info("Starting YAML configuration file validation...")
    yaml_validation_results = validate_files(package_folder_path)
    # Removed print("YAML Validation Results:", yaml_validation_results)

    # 2. Validate Dependencies and Build Size
    logger.info("Starting dependency and build size validation...")
    dependency_validation_results = validate_dependencies_and_size(
        package_folder_path,
        build_folder_path,
        max_size_mb=args.max_build_size_mb
    )
    # Removed print("Dependency Validation Results:", dependency_validation_results)

    # 3. Validate Flows and Components
    logger.info("Starting flow and component validation...")
    flow_validation_results = validate_flows_in_package(
        package_folder_path,
        max_flows=args.max_flows,
        max_sub_flows=args.max_sub_flows,
        max_components=args.max_components
    )
    # Removed print("Flow Validation Results:", flow_validation_results)

    # 4. Validate API Specifications and Definition Flows
    logger.info("Starting API specification and definition flow validation...")
    api_validation_results = validate_api_spec_and_flows(package_folder_path)
    # Removed print("API Validation Results:", api_validation_results)
    
    # 5. Code Review the flow definitions
    logger.info("Starting code review of flow definitions...")
    code_reviewer_results = review_all_files(package_folder_path)
    # Removed print("Code Review Results:", code_reviewer_results)

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
    # It's good practice to also configure logging here if the script can be run directly
    # However, the main() function already configures it.
    # If main() was not configuring it, you'd add:
    # logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(name)s - %(levelname)s - %(message)s')
    main()
