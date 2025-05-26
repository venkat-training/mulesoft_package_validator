import logging
from tabulate import tabulate

logger = logging.getLogger(__name__)

def generate_console_report(all_results):
    logger.info("Generating console report...")
    print("\n" + "="*80)
    print("VALIDATION REPORT")
    print("="*80 + "\n")

    if not all_results:
        print("No validation results to report.")
        return

    for validation_type, results in all_results.items():
        print(f"--- {validation_type.replace('_', ' ').upper()} ---")
        
        if validation_type == 'yaml_validation':
            if isinstance(results, list) and results:
                # Check for the special case where the resources directory itself was not found
                if results[0].get('file_name') == 'N/A' and results[0].get('status') == 'Error':
                    print(f"  ERROR: {results[0]['message']}")
                else:
                    mandatory_results = [item for item in results if item.get('type') == 'Mandatory']
                    optional_results = [item for item in results if item.get('type') == 'Optional']

                    if mandatory_results:
                        mandatory_data = [[item.get('file_name', 'N/A'), item.get('status', 'N/A'), item.get('message', '')] for item in mandatory_results]
                        print("\n  Mandatory Configuration Files:")
                        print(tabulate(mandatory_data, headers=["File Name", "Status", "Details"], tablefmt="grid"))
                    else:
                        print("\n  No mandatory configuration files processed or found.")
                    
                    if optional_results:
                        optional_data = [[item.get('file_name', 'N/A'), item.get('status', 'N/A'), item.get('message', '')] for item in optional_results]
                        print("\n  Optional Configuration Files:")
                        print(tabulate(optional_data, headers=["File Name", "Status", "Details"], tablefmt="grid"))
                    else:
                        print("\n  No optional configuration files found or processed.")
            elif not results:
                 print("  No YAML validation data to report (e.g., no files found or processed).")
            else: # Should not happen if validator returns a list
                print(f"  Unexpected data format for YAML validation: {results}")

        elif validation_type == 'dependency_validation':
            if isinstance(results, dict):
                build_size_mb = results.get('build_size_mb', 'N/A')
                max_size_mb = results.get('max_size_mb', 'N/A')
                size_ok = results.get('size_ok')

                size_status_text = 'Unknown'
                if size_ok is True:
                    size_status_text = 'OK'
                elif size_ok is False:
                    size_status_text = 'Exceeded Limit'
                
                # Handle build_size_mb being 'N/A' or a number for formatting
                build_size_display = f"{build_size_mb:.2f}" if isinstance(build_size_mb, (int, float)) else build_size_mb

                print(f"  Build Size: {build_size_display} MB (Max Allowed: {max_size_mb} MB) - Status: {size_status_text}")

                unused_deps = results.get('unused_dependencies')
                if unused_deps:
                    print("\n  Unused Dependencies:")
                    for dep in unused_deps:
                        print(f"    - {dep}")
                else:
                    # Check if this state is due to a POM parsing error implicitly
                    if build_size_mb == 'N/A' and not unused_deps: # Heuristic for POM error
                        print("  Could not determine unused dependencies (possible POM parsing error or no dependencies defined).")
                    else:
                        print("\n  No unused dependencies found.")
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
                
                # Handle FileNotFoundError from flow_validator
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
                if results.get('api_spec_found'):
                    if results.get('api_spec_files'):
                        for file_path in results.get('api_spec_files', []):
                            print(f"    - {file_path}")
                    else:
                        print("    - No API spec files listed.")
                
                print(f"\n  API Definition Flows Found: {'Yes' if results.get('api_definition_flow_found') else 'No'}")
                if results.get('api_definition_flow_found'):
                    if results.get('api_definition_flows'):
                        for file_path in results.get('api_definition_flows', []):
                            print(f"    - {file_path}")
                    else:
                        print("    - No API definition flow files listed.")
            else:
                print(f"  Unexpected data format for API validation: {results}")

        elif validation_type == 'code_reviewer':
            if isinstance(results, list):
                if not results:
                    print("  No code review issues or file errors found.")
                else:
                    issues_by_file = {}
                    file_errors = []

                    for item in results:
                        file_path = item.get('file_path', 'Unknown File')
                        issue_type = item.get('type', 'UnknownType')
                        message = item.get('message', 'No message provided.')

                        if issue_type in ['XMLSyntaxError', 'FileReadError', 'CheckFunctionError']:
                            file_errors.append({'file_path': file_path, 'type': issue_type, 'message': message})
                        else: # Assumed to be 'CodeReviewIssue'
                            if file_path not in issues_by_file:
                                issues_by_file[file_path] = []
                            issues_by_file[file_path].append(message)
                    
                    if file_errors:
                        print("\n  File Processing Errors:")
                        for error_item in file_errors:
                             print(f"    File: {error_item['file_path']}")
                             print(f"      Error Type: {error_item['type']}")
                             print(f"      Message: {error_item['message']}")
                    
                    if issues_by_file:
                        print("\n  Code Review Issues by File:")
                        for file_path, issues_list in issues_by_file.items():
                            print(f"    File: {file_path}")
                            for issue_msg in issues_list:
                                print(f"      - {issue_msg}")
                    
                    if not file_errors and not issues_by_file and results: # Should not happen if results has items
                        print("  Processed files but no specific issues or errors captured in known format.")

            else:
                print(f"  Unexpected data format for code reviewer: {results}")
        
        # Fallback for other validation types or if the specific handlers don't cover all cases
        elif isinstance(results, list):
            if not results:
                print("  No issues found or data to report for this section.")
            else:
                # Generic list printing if not YAML or other specific list type
                for item in results: # This part should ideally not be hit if all types are handled
                    if isinstance(item, dict): 
                        print(f"  File: {item.get('file_path', 'N/A')} - Type: {item.get('type', 'N/A')} - Message: {item.get('message', 'N/A')}")
                    else:
                        print(f"  {item}")
        elif isinstance(results, dict):
            # Generic dict printing if not dependency or other specific dict type
            for key, value in results.items():
                print(f"  {key}: {value}")
        else:
            print(f"  {results}") # Basic print for any other data type
        print("\n")

    print("="*80)
    print("END OF REPORT")
    print("="*80 + "\n")
