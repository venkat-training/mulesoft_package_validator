import argparse
from mule_validator.dependency_validator import validate_dependencies_and_size
from mule_validator.flow_validator import validate_flows_in_package
from mule_validator.code_reviewer import review_all_files
from mule_validator.components_validator import validate_mule_package
from mule_validator.api_validator import validate_api_spec_and_flows
from mule_validator.configfile_validator import validate_files


def main():

    """
    Main function to parse command-line arguments and validate the MuleSoft package.
    """
    # Create the parser
    parser = argparse.ArgumentParser(description='Validate MuleSoft package for API specifications and definition flows.')

    # Add the package folder path argument
    parser.add_argument(
        'package_folder_path',
        type=str,
        help='The path to the MuleSoft package folder to validate.'
    )

    # Parse the command-line arguments
    args = parser.parse_args()

    # Define the paths to your MuleSoft package and build folder
    #package_folder_path = 'C:/Users/venkats/OneDrive - SBS Corporation/Documents/SBS/ws/mulesoft/' + 'sbs-eis-integrationservices'
    #build_folder_path = 'C:/Users/venkats/OneDrive - SBS Corporation/Documents/SBS/ws/mulesoft/' + 'sbs-eis-integrationservices'
    
    package_folder_path = args.package_folder_path
    build_folder_path = args.package_folder_path
    #1. Validate YAML Files
    print("Validating YAML configuration files...")
    yaml_validation_results = validate_files(package_folder_path)
    print("YAML Validation Results:", yaml_validation_results)

    # 2. Validate Dependencies and Build Size
    print("\nValidating dependencies and build size...")
    dependency_validation_results = validate_dependencies_and_size(package_folder_path, build_folder_path)
    print("Dependency Validation Results:", dependency_validation_results)

    # 3. Validate Flows and Components
    print("\nValidating flows and components...")
    flow_validation_results = validate_flows_in_package(package_folder_path)
    print("Flow Validation Results:", flow_validation_results)

    # 4. Validate API Specifications and Definition Flows
    print("\nValidating API specifications and definition flows...")
    api_validation_results = validate_api_spec_and_flows(package_folder_path)
    print("API Validation Results:", api_validation_results)

    
    # 5. Code Review the flow definitions
    print("\nReviewing flows...")
    code_reviewer_results = review_all_files(package_folder_path)
    print("Code Review Results:", code_reviewer_results)

    # 6. Validate Components
    print("\nValidating Components...")
    components_validator_results = validate_mule_package(package_folder_path)
    print("Components Validation Results:", components_validator_results)

    

    # Combine all results
    print("\nAll validations completed.")
    all_results = {
        'yaml_validation': yaml_validation_results,
        'dependency_validation': dependency_validation_results,
        'flow_validation': flow_validation_results,
        'api_validation': api_validation_results,
        'code_reviewer' : code_reviewer_results,
        'components_validator' : components_validator_results
    }
    
    # Output combined results if needed
    print("\nSummary of all validation results:", all_results)

if __name__ == '__main__':
    main()
