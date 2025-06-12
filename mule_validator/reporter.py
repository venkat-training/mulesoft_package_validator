import logging
from tabulate import tabulate
from typing import Dict, Any, Optional, List

"""
Generates a human-readable, text-based validation report to the console.

This module takes the aggregated results from all validation checks and formats
them into a structured console output. It uses the `tabulate` library to display
list-based data in tables and provides specific formatting for different types
of validation results, including security warnings.
"""

logger = logging.getLogger(__name__)

def _print_security_warning(
    warning_type: str,
    file_path: str,
    location: Optional[str],
    issue: str,
    value_excerpt: Optional[str] = None
) -> None:
    """
    Prints a standardized security warning message to the console.

    Args:
        warning_type (str): The type of security warning (e.g., "YAML Secret", "POM Secret").
        file_path (str): The path to the file where the warning was found.
        location (Optional[str]): Specific location within the file (e.g., XML path, key path).
        issue (str): Description of the security issue.
        value_excerpt (Optional[str], optional): An excerpt of the problematic value. Defaults to None.
    """
    print(f"\n  [SECURITY WARNING] ({warning_type})")
    print(f"    File: {file_path}")
    if location:
        print(f"    Location: {location}")
    print(f"    Issue: {issue}")
    if value_excerpt:
        print(f"    Value Excerpt: \"{value_excerpt}\"")

def generate_console_report(all_results: Dict[str, Any]) -> None:
    """
    Generates and prints a comprehensive validation report to the console.

    The function iterates through the `all_results` dictionary, which should
    contain results from various validation modules keyed by a `validation_type` string
    (e.g., 'yaml_validation', 'dependency_validation', 'code_reviewer').

    For each validation type, it applies specific formatting logic:
    - **yaml_validation**: Displays mandatory and optional file checks in tables,
      and lists security warnings using `_print_security_warning`.
    - **dependency_validation**: Shows build size, lists unused dependencies,
      POM parsing errors, and POM security warnings.
    - **flow_validation**: Tabulates flow, sub-flow, and component counts against limits.
    - **api_validation**: Reports on the presence of API specifications and definition flows.
    - **code_reviewer**: Lists file processing errors, standard code review issues,
      and XML security warnings.
    - Other types are handled with a generic fallback.

    The report includes a summary of total security warnings found across all sections.

    Args:
        all_results (Dict[str, Any]): A dictionary where keys are strings
            representing the validation type (e.g., 'yaml_validation') and
            values are the corresponding results from the validator modules.
            The structure of the values varies depending on the validation type.
    """
    logger.info("Generating console report...")
    print("\n" + "="*80)
    print("VALIDATION REPORT")
    print("="*80 + "\n")

    if not all_results:
        print("No validation results to report.")
        return

    total_security_warnings = 0

    for validation_type, results in all_results.items():
        print(f"--- {validation_type.replace('_', ' ').upper()} ---")
        
        if validation_type == 'yaml_validation':
            if isinstance(results, list) and results:
                # Check for the special case where the resources directory itself was not found
                if results[0].get('file_name') == 'N/A' and results[0].get('status') == 'Error' and results[0].get('type') == 'Setup':
                    print(f"  ERROR: {results[0]['message']}")
                else:
                    # Separate findings: standard (Valid, Missing, InvalidSyntax) and security warnings
                    standard_findings = []
                    security_warnings = []
                    for item in results:
                        if item.get('status') == 'SecurityWarning':
                            security_warnings.append(item)
                            total_security_warnings +=1
                        else:
                            standard_findings.append(item)
                    
                    mandatory_results = [item for item in standard_findings if item.get('type') == 'Mandatory']
                    optional_results = [item for item in standard_findings if item.get('type') == 'Optional']

                    if mandatory_results:
                        mandatory_data = [[item.get('file_name', 'N/A'), item.get('status', 'N/A'), item.get('message', '')] for item in mandatory_results]
                        print("\n  Mandatory Configuration Files (Syntax & Presence):")
                        print(tabulate(mandatory_data, headers=["File Name", "Status", "Details"], tablefmt="grid"))
                    else:
                        print("\n  No mandatory configuration files processed or found for standard checks.")
                    
                    if optional_results:
                        optional_data = [[item.get('file_name', 'N/A'), item.get('status', 'N/A'), item.get('message', '')] for item in optional_results]
                        print("\n  Optional Configuration Files (Syntax & Presence):")
                        print(tabulate(optional_data, headers=["File Name", "Status", "Details"], tablefmt="grid"))
                    else:
                        print("\n  No optional configuration files found or processed for standard checks.")
                    
                    if security_warnings:
                        print("\n  YAML Security Warnings:")
                        for warning in security_warnings:
                            details = warning.get('details', {})
                            _print_security_warning(
                                warning_type="YAML Secret",
                                file_path=warning.get('file_name', 'N/A'),
                                location=details.get('path', 'N/A'),
                                issue=warning.get('message', 'No specific message.') \
                                    .replace(f"Potential secret at path '{details.get('path', '')}'. Key: '{details.get('key', '')}'. Type: {details.get('issue_type', '')}. Description: ", ""), # Make message more concise
                                value_excerpt=details.get('value_excerpt')
                            )
            elif not results: # Empty list means all files were valid and no secrets found
                 print("  All YAML files processed are valid and no security warnings detected.")
            else:
                print(f"  Unexpected data format for YAML validation: {results}")

        elif validation_type == 'dependency_validation':
            if isinstance(results, dict):
                build_size_mb = results.get('build_size_mb', 'N/A')
                max_size_mb = results.get('max_size_mb', 'N/A')
                size_ok = results.get('size_ok')
                build_size_error = results.get('build_size_error')

                size_status_text = 'Unknown'
                if build_size_error:
                    size_status_text = f"Error ({build_size_error})"
                elif size_ok is True:
                    size_status_text = 'OK'
                elif size_ok is False:
                    size_status_text = 'Exceeded Limit'
                
                build_size_display = f"{build_size_mb:.2f}" if isinstance(build_size_mb, (int, float)) else build_size_mb
                print(f"  Build Size: {build_size_display} MB (Max Allowed: {max_size_mb} MB) - Status: {size_status_text}")

                unused_deps = results.get('unused_dependencies')
                if unused_deps:
                    print("\n  Unused Dependencies:")
                    for dep in unused_deps:
                        print(f"    - {dep}")
                else:
                    if not results.get('pom_parsing_error'): # Only say no unused if POM was parsed ok
                        print("\n  No unused dependencies found (or POM not parsed).")

                pom_parsing_error = results.get('pom_parsing_error')
                if pom_parsing_error:
                    print(f"\n  POM Parsing Error: {pom_parsing_error}")

                pom_security_warnings = results.get('pom_security_warnings', [])
                if pom_security_warnings:
                    print("\n  POM Security Warnings:")
                    total_security_warnings += len(pom_security_warnings)
                    for warning in pom_security_warnings:
                        _print_security_warning(
                            warning_type="POM Secret",
                            file_path=warning.get('file_path', 'pom.xml'),
                            location=f"Element: <{warning.get('xml_path', 'N/A')}>" + (f" / Attribute: {warning.get('attribute_name')}" if warning.get('attribute_name') else ""),
                            issue=warning.get('message', 'No specific message.'),
                            value_excerpt=warning.get('value_excerpt')
                        )
            else:
                print(f"  Unexpected data format for dependency validation: {results}")

        elif validation_type == 'flow_validation':
            if isinstance(results, dict):
                total_counts = results.get('total_counts', {})
                flows_count = total_counts.get('flows', 'N/A')
                sub_flows_count = total_counts.get('sub_flows', 'N/A')
                components_count = total_counts.get('components', 'N/A')

                max_flows = results.get('max_flows_limit', 'N/A')
                max_sub_flows = results.get('max_sub_flows_limit', 'N/A')
                max_components = results.get('max_components_limit', 'N/A')

                flows_status = 'OK' if results.get('flows_ok', True) else 'Exceeded'
                sub_flows_status = 'OK' if results.get('sub_flows_ok', True) else 'Exceeded'
                components_status = 'OK' if results.get('components_ok', True) else 'Exceeded'
                
                if results.get('total_counts') is None and results.get('message'):
                     print(f"  ERROR: {results.get('message')}")
                else:
                    table_data = [
                        ["Flows", flows_count, max_flows, flows_status],
                        ["Sub-flows", sub_flows_count, max_sub_flows, sub_flows_status],
                        ["Components", components_count, max_components, components_status]
                    ]
                    print(tabulate(table_data, headers=["Category", "Count", "Limit", "Status"], tablefmt="grid"))
            else:
                print(f"  Unexpected data format for flow validation: {results}")

        elif validation_type == 'api_validation':
            if isinstance(results, dict):
                print(f"  API Specifications Found: {'Yes' if results.get('api_spec_found') else 'No'}")
                if results.get('api_spec_found') and results.get('api_spec_files'):
                    for file_path in results.get('api_spec_files', []): print(f"    - {file_path}")
                
                print(f"\n  API Definition Flows Found: {'Yes' if results.get('api_definition_flow_found') else 'No'}")
                if results.get('api_definition_flow_found') and results.get('api_definition_flows'):
                    for file_path in results.get('api_definition_flows', []): print(f"    - {file_path}")
            else:
                print(f"  Unexpected data format for API validation: {results}")

        elif validation_type == 'code_reviewer':
            if isinstance(results, list):
                if not results:
                    print("  No code review issues or file errors found.")
                else:
                    standard_issues_by_file = {}
                    security_warnings = []
                    file_errors = [] # XMLSyntaxError, FileReadError, CheckFunctionError, GenericProcessingError

                    for item in results:
                        issue_type = item.get('type', 'UnknownType')
                        if issue_type in ['HardcodedSecretXML', 'SuspiciousValueXML', 'InsecurePropertyUseXML']:
                            security_warnings.append(item)
                            total_security_warnings += 1
                        elif issue_type in ['XMLSyntaxError', 'FileReadError', 'CheckFunctionError', 'GenericProcessingError']:
                            file_errors.append(item)
                        else: # Assumed to be 'CodeReviewIssue' (standard, non-security)
                            file_path = item.get('file_path', 'Unknown File')
                            if file_path not in standard_issues_by_file:
                                standard_issues_by_file[file_path] = []
                            standard_issues_by_file[file_path].append(item.get('message', 'No message provided.'))
                    
                    if file_errors:
                        print("\n  File Processing Errors (Code Review):")
                        for error_item in file_errors:
                             print(f"    File: {error_item['file_path']}")
                             print(f"      Error Type: {error_item['type']}")
                             print(f"      Message: {error_item['message']}")
                    
                    if standard_issues_by_file:
                        print("\n  Standard Code Review Issues by File:")
                        for file_path, issues_list in standard_issues_by_file.items():
                            print(f"    File: {file_path}")
                            for issue_msg in issues_list:
                                print(f"      - {issue_msg}")
                    
                    if security_warnings:
                        print("\n  XML Code Security Warnings:")
                        for warning in security_warnings:
                            location = f"Element: <{warning.get('xml_path', 'N/A')}>"
                            if warning.get('attribute_name'):
                                location += f" / Attribute: {warning.get('attribute_name')}"
                            
                            _print_security_warning(
                                warning_type=warning.get('issue_type', 'XML Security Issue'),
                                file_path=warning.get('file_path', 'N/A'),
                                location=location,
                                issue=warning.get('message', 'No specific message.'),
                                value_excerpt=warning.get('value_excerpt')
                            )
                    
                    if not file_errors and not standard_issues_by_file and not security_warnings and results:
                        print("  Processed files but no specific issues or errors captured in known format.")
            else:
                print(f"  Unexpected data format for code reviewer: {results}")
        
        # Fallback for other validation types
        elif isinstance(results, list) and not results:
            print("  No issues found or data to report for this section.")
        elif isinstance(results, dict) and not results: # Empty dict
             print("  No data to report for this section.")
        else: # Should not be hit if all types are handled explicitly or are empty
            print(f"  Unhandled or non-empty results: {results}")
        print("\n")

    print("="*80)
    if total_security_warnings > 0:
        print(f"TOTAL SECURITY WARNINGS FOUND: {total_security_warnings}")
        print("="*80)
    print("END OF REPORT")
    print("="*80 + "\n")
