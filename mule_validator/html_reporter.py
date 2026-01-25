"""
Generates an HTML report from MuleSoft project validation results.

This module takes a dictionary containing various validation results (from code review,
YAML checks, dependency analysis, etc.) and an HTML template string. It populates
the placeholders in the template with formatted data from the results to produce
a single HTML output string.

The module uses the `tabulate` library to format list-based data into HTML tables.
It also includes functionality to fetch the current Git branch name.
Additionally, this version includes threshold warnings for:
- Build size
- Total flows
- Sub-flows
- Total components
and support for orphan checker results.
"""

import subprocess
from tabulate import tabulate
from typing import Any, Union, List, Dict

def get_current_git_branch() -> str:
    """
    Tries to get the current Git branch name using the `git` command.

    Executes `git rev-parse --abbrev-ref HEAD` with a timeout of 5 seconds.
    If the command fails (e.g., not a git repository, git not installed, timeout),
    it returns "Unknown".

    Returns:
        str: The current Git branch name or "Unknown" if it cannot be determined.
    """
    try:
        process_result = subprocess.run(
            ['git', 'rev-parse', '--abbrev-ref', 'HEAD'],
            capture_output=True, text=True, check=True, timeout=5
        )
        return process_result.stdout.strip()
    except (subprocess.CalledProcessError, FileNotFoundError, subprocess.TimeoutExpired):
        return "Unknown"

def _format_data_to_html(data, headers="firstrow"):
    """
    Helper function to format various Python data structures into simple HTML.

    - If `data` is a list of lists, it's formatted as an HTML table using `tabulate`.
    - If `data` is a list of strings or other items, it's formatted as an HTML unordered list.
    - If `data` is a dictionary, it's formatted as a simple two-column HTML table (Key, Value).
    - If `data` is a string, it's wrapped in a `<p>` tag.
    - Other data types are converted to string and wrapped in a `<p>` tag.
    - If `data` is empty (None, empty list, empty dict), it returns "<p>No data available.</p>".

    Args:
        data (Any): The data to format. Can be a list, dict, string, etc.
        headers (Union[str, List[str]], optional): For list-of-lists data,
            specifies table headers. Defaults to "firstrow".
            Passed directly to `tabulate`.

    Returns:
        str: An HTML string representation of the input data.
    """
    if not data:
        return "<p>No data available.</p>"

    if isinstance(data, list):
        if not data:  # Empty list
            return "<p>No data available.</p>"
        if all(isinstance(item, list) for item in data):  # List of lists
            return tabulate(data, headers=headers, tablefmt='html')
        elif all(isinstance(item, str) for item in data):  # List of strings
            items_html = "".join(f"<li>{item}</li>" for item in data)
            return f"<ul>{items_html}</ul>"
        else:  # List of other items
            items_html = "".join(f"<li>{str(item)}</li>" for item in data)
            return f"<ul>{items_html}</ul>"
    elif isinstance(data, dict):
        if not data:  # Empty dict
            return "<p>No data available.</p>"
        # Simple key-value table for dicts
        table_rows = "".join(f"<tr><td>{key}</td><td>{str(value)}</td></tr>" for key, value in data.items())
        return f"<table><thead><tr><th>Key</th><th>Value</th></tr></thead><tbody>{table_rows}</tbody></table>"
    elif isinstance(data, str):
        return f"<p>{data}</p>"  # Wrap plain strings in a paragraph
    else:  # For other data types (int, bool, etc.)
        return f"<p>{str(data)}</p>"

def generate_html_report(all_results: Dict[str, Any], template_string: str) -> str:
    """
    Generates an HTML report by populating placeholders in a template string
    with validation results.

    This version includes threshold warnings and orphan checker results.
    """
    html_content = template_string

    # -------------------------
    # Threshold Warnings
    # -------------------------
    thresholds = all_results.get("thresholds", {})
    threshold_warnings = []

    max_build_size = thresholds.get("max_build_size_mb", 100)
    max_flows = thresholds.get("max_flows", 100)
    max_sub_flows = thresholds.get("max_sub_flows", 50)
    max_components = thresholds.get("max_components", 500)

    build_size_mb = all_results.get("dependency_validation", {}).get("build_size_mb", 0)
    if build_size_mb > max_build_size:
        threshold_warnings.append(f"Build size {build_size_mb} MB exceeds maximum allowed {max_build_size} MB.")

    flow_stats = all_results.get("flow_validation", {})
    total_flows = flow_stats.get("total_flows", 0)
    total_sub_flows = flow_stats.get("total_sub_flows", 0)
    total_components = flow_stats.get("total_components", 0)

    if total_flows > max_flows:
        threshold_warnings.append(f"Total flows {total_flows} exceed maximum allowed {max_flows}.")
    if total_sub_flows > max_sub_flows:
        threshold_warnings.append(f"Total sub-flows {total_sub_flows} exceed maximum allowed {max_sub_flows}.")
    if total_components > max_components:
        threshold_warnings.append(f"Total components {total_components} exceed maximum allowed {max_components}.")

    if threshold_warnings:
        warnings_html = "<ul>" + "".join(f"<li class='warning'>{msg}</li>" for msg in threshold_warnings) + "</ul>"
        html_content = html_content.replace("{{threshold_warnings}}", warnings_html)
    else:
        html_content = html_content.replace("{{threshold_warnings}}", "<p>No threshold warnings.</p>")

    # -------------------------
    # 1. Code Review Issues
    # -------------------------
    code_review_issues = all_results.get('code_reviewer_issues')
    if code_review_issues:
        code_review_table = tabulate(code_review_issues, headers=["File Name", "Status", "Issue"], tablefmt='html')
        html_content = html_content.replace('{{code_review_issues_table}}', code_review_table)
    else:
        html_content = html_content.replace('{{code_review_issues_table}}', "<p>No code review issues found.</p>")

    # 2. YAML Validation Results
    yaml_results = all_results.get('yaml_validation')
    if yaml_results:
        html_content = html_content.replace('{{yaml_validation_results_table}}', _format_data_to_html(yaml_results))
    else:
        html_content = html_content.replace('{{yaml_validation_results_table}}', "<p>No YAML validation issues found.</p>")

    # 3. Dependency Validation Results
    dependency_results = all_results.get('dependency_validation')
    dep_tables = []
    has_dep_issues = False
    if isinstance(dependency_results, dict) and dependency_results:
        for pom_path, dep_info in dependency_results.items():
            if pom_path == "build_size_mb":  # skip build size entry
                continue
            rows = []
            if dep_info.get("missing_jars"):
                for jar in dep_info["missing_jars"]:
                    rows.append(["Missing Artifact", jar])
            if dep_info.get("unresolved_dependencies"):
                for dep in dep_info["unresolved_dependencies"]:
                    rows.append(["Unresolved Dependency", dep])
            if dep_info.get("duplicate_dependencies"):
                for dep in dep_info["duplicate_dependencies"]:
                    rows.append(["Duplicate Dependency", dep])
            if rows:
                has_dep_issues = True
                table_html = tabulate(rows, headers=["Type", "Value"], tablefmt='html')
                dep_tables.append(f"<h4>{pom_path}</h4>{table_html}")
        if has_dep_issues:
            html_content = html_content.replace('{{dependency_validation_results_table}}', "".join(dep_tables))
        else:
            html_content = html_content.replace('{{dependency_validation_results_table}}', "<p>No dependency issues found.</p>")
    else:
        html_content = html_content.replace('{{dependency_validation_results_table}}', "<p>No dependency issues found.</p>")

    # 4. Flow Validation Results
    flow_results = all_results.get('flow_validation')
    if isinstance(flow_results, list) and flow_results and all(isinstance(item, dict) for item in flow_results):
        headers = list(flow_results[0].keys())
        table_data = [[item.get(h, '') for h in headers] for item in flow_results]
        flow_table = tabulate(table_data, headers=headers, tablefmt='html')
        html_content = html_content.replace('{{flow_validation_results_table}}', flow_table)
    elif flow_results:
        html_content = html_content.replace('{{flow_validation_results_table}}', _format_data_to_html(flow_results))
    else:
        html_content = html_content.replace('{{flow_validation_results_table}}', "<p>No flow validation issues found.</p>")

    # 5. API Validation Results
    api_results = all_results.get('api_validation')
    if isinstance(api_results, list) and api_results and all(isinstance(item, dict) for item in api_results):
        headers = list(api_results[0].keys())
        table_data = [[item.get(h, '') for h in headers] for item in api_results]
        api_table = tabulate(table_data, headers=headers, tablefmt='html')
        html_content = html_content.replace('{{api_validation_results_table}}', api_table)
    elif api_results:
        html_content = html_content.replace('{{api_validation_results_table}}', _format_data_to_html(api_results))
    else:
        html_content = html_content.replace('{{api_validation_results_table}}', "<p>No API validation issues found.</p>")

    # 6. Project Uses Mule Secure Properties
    secure_props_status = all_results.get('project_uses_secure_properties')
    if secure_props_status is not None:
        html_content = html_content.replace('{{secure_properties_status}}', f"<p>{str(secure_props_status)}</p>")
    else:
        html_content = html_content.replace('{{secure_properties_status}}', "<p>No secure properties validation result.</p>")

    # 7. Logging Validation Results
    logging_results = all_results.get('logging_validation')
    if isinstance(logging_results, dict) and (logging_results.get("logger_issues") or logging_results.get("log4j_warnings")):
        log_html = ""
        # Logger issues
        logger_issues = logging_results.get("logger_issues")
        if logger_issues:
            # If logger_issues is a list of dicts, tabulate as table
            if isinstance(logger_issues, list) and logger_issues and isinstance(logger_issues[0], dict):
                headers = list(logger_issues[0].keys())
                table_data = [[item.get(h, '') for h in headers] for item in logger_issues]
                log_html += "<h4>Logger Issues</h4>"
                log_html += tabulate(table_data, headers=headers, tablefmt='html')
            else:
                log_html += "<h4>Logger Issues</h4>"
                log_html += _format_data_to_html(logger_issues)
        # Log4j warnings
        log4j_warnings = logging_results.get("log4j_warnings")
        if log4j_warnings:
            log_html += "<h4>Log4j Warnings</h4>"
            log_html += _format_data_to_html(log4j_warnings)
        html_content = html_content.replace('{{logging_validation_results_table}}', log_html)
    else:
        html_content = html_content.replace('{{logging_validation_results_table}}', "<p>No logging issues found.</p>")

    # 8. Orphan Checker Results
    orphan_results = all_results.get("orphan_checker")
    html_content = html_content.replace('{{orphan_validation_results_table}}', _format_data_to_html(orphan_results))

    # Fallbacks for any placeholders not explicitly handled
    placeholders = ['code_review_issues_table', 'yaml_validation_results_table',
                    'dependency_validation_results_table', 'flow_validation_results_table',
                    'api_validation_results_table', 'secure_properties_status',
                    'logging_validation_results_table']
    for ph in placeholders:
        html_content = html_content.replace(f'{{{{{ph}}}}}', "<p>Data not available.</p>")

    # Add Git branch name
    branch_name = all_results.get('git_branch_name', 'Unknown')
    html_content = html_content.replace('{{git_branch_name}}', branch_name)

    # Add report start and end time
    html_content = html_content.replace('{{report_start_time}}', all_results.get('report_start_time', 'N/A'))
    html_content = html_content.replace('{{report_end_time}}', all_results.get('report_end_time', 'N/A'))
    html_content = html_content.replace('{{report_duration}}', all_results.get('report_duration', 'N/A'))

    return html_content
