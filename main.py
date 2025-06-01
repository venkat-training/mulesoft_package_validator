"""
Main entry point for the MuleSoft Package Validator CLI tool.

This script orchestrates the validation of a MuleSoft package by invoking various
validators for dependencies, flows, API specifications, YAML configurations,
MuleSoft code review, and component structure. It takes the package folder path
as a command-line argument and prints a summary of all validation results.
"""
import argparse
from mule_validator.dependency_validator import validate_all_projects
from mule_validator.flow_validator import validate_flows_in_package
from mule_validator.code_reviewer import review_all_files
from mule_validator.api_validator import validate_api_spec_and_flows
from mule_validator.configfile_validator import validate_files
from tabulate import tabulate
from mule_validator.html_reporter import generate_html_report


def main():
    """
    Main function to parse command-line arguments and orchestrate the validation
    of a MuleSoft package.

    The validation process includes:
    1. Code Review: Analyzes Mule XML files for issues and checks for the use of
       Mule Secure Properties. This is done first as its output (`project_uses_secure_properties`)
       is required by the YAML configuration validator.
    2. YAML Configuration Validation: Checks for presence, syntax, and content of
       YAML configuration files, considering if secure properties are used.
    3. Dependency and Build Size Validation: Validates Maven dependencies and build size.
    4. Flow and Component Validation: Validates the structure and components within Mule flows.
    5. API Specification and Definition Flow Validation: Checks API RAML specs against
       their corresponding Mule flow implementations.
    6. General Component Validation: Performs additional checks on Mule components.

    Results from all validators are collected and printed in a summary.
    """
    # Create the parser for command-line arguments
    parser = argparse.ArgumentParser(
        description='Validate a MuleSoft package, checking API specifications, '
                    'definition flows, YAML configurations, and more.'
    )

    # Add the package folder path argument
    parser.add_argument(
        'package_folder_path',
        type=str,
        help='The path to the MuleSoft package folder to validate.'
    )

    # Add the optional report file argument
    parser.add_argument(
        '--report-file',
        type=str,
        help='Optional. The path to save the HTML validation report.'
    )

    # Parse the command-line arguments
    args = parser.parse_args()

    # Define the paths to your MuleSoft package and build folder
    # These are now derived from the command-line arguments.
    # Example: package_folder_path = 'path/to/your/mulesoft/project'
    # Example: build_folder_path = 'path/to/your/mulesoft/project' (often same as package for these validations)
    
    package_folder_path = args.package_folder_path
    build_folder_path = args.package_folder_path # Assuming build path is same as package path for these validators

    # --- Orchestrate Validation Steps ---

    # Step 1: Code Review (performed first as its output is needed by YAML validation)
    # This reviews Mule XML files for coding standards, issues, and detects
    # if Mule Secure Properties configuration is used anywhere in the project.
    print("\nReviewing flows and code structure...")
    issues_data_from_code_reviewer, project_uses_secure_properties = review_all_files(package_folder_path)
    print("\nCode Review Issues Found:")
    if issues_data_from_code_reviewer:
        print(tabulate(issues_data_from_code_reviewer, headers=["File Name", "Status", "Issue"], tablefmt="grid"))
    else:
        print("No code review issues found.")
    print(f"Project uses Mule Secure Properties: {project_uses_secure_properties}")

    # Step 2: Validate YAML Files
    # This validator now uses `project_uses_secure_properties` to apply specific
    # content rules (e.g., warning if plaintext secrets are found when encryption is available).
    print("\nValidating YAML configuration files...")
    yaml_validation_results = validate_files(package_folder_path, project_uses_secure_properties)
    print("YAML Validation Results:", yaml_validation_results)

    # Step 3: Validate Dependencies and Build Size
    print("\nValidating dependencies and build size...")
    dependency_validation_results = validate_all_projects(package_folder_path)
    print("Dependency Validation Results:", dependency_validation_results)

    # Step 4: Validate Flows and Components within flows
    print("\nValidating flows and components...")
    flow_validation_results = validate_flows_in_package(package_folder_path)
    print("Flow Validation Results:", flow_validation_results)

    # Step 5: Validate API Specifications against their Definition Flows
    print("\nValidating API specifications and definition flows...")
    api_validation_results = validate_api_spec_and_flows(package_folder_path)
    print("API Validation Results:", api_validation_results)

    # Note: Code Review (previously step 5 in some orderings) results were processed earlier.

    # Combine all validation results into a single dictionary for a comprehensive summary.
    print("\nAll validations completed.")
    all_results = {
        'yaml_validation': yaml_validation_results,  # Results from YAML file checks
        'dependency_validation': dependency_validation_results,  # Results from POM and build size checks
        'flow_validation': flow_validation_results,  # Results from Mule flow structure checks
        'api_validation': api_validation_results,  # Results from API spec vs. flow implementation checks
        'code_reviewer_issues': issues_data_from_code_reviewer,  # List of issues from code review
        'project_uses_secure_properties': project_uses_secure_properties  # Boolean flag from code review
    }
    
    # Output the combined results dictionary. This can be consumed by other tools or scripts if needed.
    print("\nSummary of all validation results:", all_results)

    # Generate HTML report if the --report-file argument is provided
    if args.report_file:
        try:
            # Placeholder for reading the template file
            # In a future step, this will be replaced with a call to a function in html_reporter.py
            # that properly populates the template.
            try:
                with open('mule_validator/report_template.html', 'r') as f_template:
                    template_content = f_template.read()
                
                # Generate the actual HTML content using the imported function
                report_content = generate_html_report(all_results, template_content)
                
                with open(args.report_file, 'w') as f_report:
                    f_report.write(report_content)
                print(f"\nHTML report generated successfully at: {args.report_file}")
            except FileNotFoundError:
                print(f"\nError: HTML template file not found at mule_validator/report_template.html. Report not generated.")
            except Exception as e:
                print(f"\nError generating HTML report: {e}")

        except Exception as e:
            print(f"\nAn error occurred while trying to generate the HTML report: {e}")


if __name__ == '__main__':
    # This ensures main() is called only when the script is executed directly.
    main()
