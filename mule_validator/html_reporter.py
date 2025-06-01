import subprocess
from tabulate import tabulate

def get_current_git_branch():
    """Tries to get the current Git branch name."""
    try:
        process_result = subprocess.run(
            ['git', 'rev-parse', '--abbrev-ref', 'HEAD'],
            capture_output=True, text=True, check=True, timeout=5
        )
        return process_result.stdout.strip()
    except (subprocess.CalledProcessError, FileNotFoundError, subprocess.TimeoutExpired) as e:
        # Log this error if logging is set up in this module, or handle silently
        # print(f"Could not get Git branch name: {e}") # Optional: for debugging
        return "Unknown"

def _format_data_to_html(data, headers="firstrow"):
    """
    Helper function to format various data structures to HTML.
    - If data is a list of lists, it's treated as tabular data.
    - If data is a list of strings, it's formatted as an unordered list.
    - If data is a dictionary, it's formatted as a definition list.
    - If data is a simple string, it's returned as is.
    - If data is None or empty, a placeholder message is returned.
    """
    if not data:
        return "<p>No data available.</p>"

    if isinstance(data, list):
        if not data:
            return "<p>No data available.</p>"
        if all(isinstance(item, list) for item in data): # List of lists
            return tabulate(data, headers=headers, tablefmt='html')
        elif all(isinstance(item, str) for item in data): # List of strings
            items_html = "".join(f"<li>{item}</li>" for item in data)
            return f"<ul>{items_html}</ul>"
        else: # Mixed list or other complex list structure - convert to string for now
            items_html = "".join(f"<li>{str(item)}</li>" for item in data)
            return f"<ul>{items_html}</ul>"
    elif isinstance(data, dict):
        if not data:
            return "<p>No data available.</p>"
        # For dictionaries, especially if they are simple key-value, a definition list or simple table might be good.
        # Using a simple table for now for key-value pairs.
        table_rows = "".join(f"<tr><td>{key}</td><td>{value}</td></tr>" for key, value in data.items())
        return f"<table><thead><tr><th>Key</th><th>Value</th></tr></thead><tbody>{table_rows}</tbody></table>"
    elif isinstance(data, str):
        return f"<p>{data}</p>"
    else:
        return f"<p>{str(data)}</p>"


def generate_html_report(all_results, template_string):
    """
    Generates an HTML report by populating a template string with validation results.

    Args:
        all_results (dict): A dictionary containing all validation results.
        template_string (str): The HTML template content as a string.

    Returns:
        str: The populated HTML string.
    """
    html_content = template_string

    # 1. Code Review Issues
    code_review_issues = all_results.get('code_reviewer_issues')
    if code_review_issues:
        # Assuming code_review_issues is a list of lists with headers ["File Name", "Status", "Issue"]
        # as per the tabulate call in main.py
        code_review_table = tabulate(code_review_issues, headers=["File Name", "Status", "Issue"], tablefmt='html')
        html_content = html_content.replace('{{code_review_issues_table}}', code_review_table)
    else:
        html_content = html_content.replace('{{code_review_issues_table}}', "<p>No code review issues found.</p>")

    # 2. YAML Validation Results
    yaml_results = all_results.get('yaml_validation')
    # Based on `main.py`, `yaml_validation_results` is printed directly, suggesting it might be a string or simple list.
    # The `validate_files` function in `configfile_validator.py` returns a list of strings.
    html_content = html_content.replace('{{yaml_validation_results_table}}', _format_data_to_html(yaml_results))

    # 3. Dependency Validation Results
    dependency_results = all_results.get('dependency_validation')
    # `validate_dependencies_and_size` returns a dictionary.
    html_content = html_content.replace('{{dependency_validation_results_table}}', _format_data_to_html(dependency_results))

    # 4. Flow Validation Results
    flow_results = all_results.get('flow_validation')
    # `validate_flows_in_package` returns a list of dictionaries, where each dict is a flow issue.
    # Let's prepare it for tabulate if it's a list of dicts.
    if isinstance(flow_results, list) and flow_results and all(isinstance(item, dict) for item in flow_results):
        # Extract headers from the keys of the first dictionary, and then the data
        headers = list(flow_results[0].keys())
        table_data = [[item.get(h, '') for h in headers] for item in flow_results]
        flow_table = tabulate(table_data, headers=headers, tablefmt='html')
        html_content = html_content.replace('{{flow_validation_results_table}}', flow_table)
    elif flow_results: # If not list of dicts, use generic formatter
        html_content = html_content.replace('{{flow_validation_results_table}}', _format_data_to_html(flow_results))
    else:
        html_content = html_content.replace('{{flow_validation_results_table}}', "<p>No flow validation data available or no issues found.</p>")


    # 5. API Validation Results
    api_results = all_results.get('api_validation')
    # `validate_api_spec_and_flows` returns a list of dictionaries.
    if isinstance(api_results, list) and api_results and all(isinstance(item, dict) for item in api_results):
        headers = list(api_results[0].keys())
        table_data = [[item.get(h, '') for h in headers] for item in api_results]
        api_table = tabulate(table_data, headers=headers, tablefmt='html')
        html_content = html_content.replace('{{api_validation_results_table}}', api_table)
    elif api_results:
        html_content = html_content.replace('{{api_validation_results_table}}', _format_data_to_html(api_results))
    else:
        html_content = html_content.replace('{{api_validation_results_table}}', "<p>No API validation data available or no issues found.</p>")

    # 7. Project Uses Mule Secure Properties
    secure_props_status = all_results.get('project_uses_secure_properties')
    html_content = html_content.replace('{{secure_properties_status}}', f"<p>{str(secure_props_status)}</p>")
    
    # Fallback for any placeholders not explicitly handled, to avoid them showing in the report
    html_content = html_content.replace('{{code_review_issues_table}}', "<p>Data not available.</p>")
    html_content = html_content.replace('{{yaml_validation_results_table}}', "<p>Data not available.</p>")
    html_content = html_content.replace('{{dependency_validation_results_table}}', "<p>Data not available.</p>")
    html_content = html_content.replace('{{flow_validation_results_table}}', "<p>Data not available.</p>")
    html_content = html_content.replace('{{api_validation_results_table}}', "<p>Data not available.</p>")
    html_content = html_content.replace('{{secure_properties_status}}', "<p>Data not available.</p>")

    # Add Git branch name
    branch_name = get_current_git_branch()
    html_content = html_content.replace('{{git_branch_name}}', branch_name)
    # Fallback for branch name placeholder if not in template (though it should be)
    html_content = html_content.replace('{{git_branch_name}}', "<p>Git branch: Unknown</p>")


    return html_content
