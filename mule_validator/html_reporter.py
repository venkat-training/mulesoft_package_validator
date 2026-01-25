"""
html_reporter.py

Generates an HTML report from MuleSoft project validation results.

This module takes a dictionary containing validation results (code review,
YAML checks, dependency analysis, flow/API validation, logging checks, etc.)
and an HTML template string. It populates the placeholders in the template
with formatted HTML tables or lists for easy reporting.

Dependencies:
- tabulate: For converting lists/dicts into HTML tables.
"""

import subprocess
from tabulate import tabulate
from typing import Any, Union, List, Dict

# -------------------------
# Severity mapping for issues
# -------------------------
SEVERITY = {
    "invalid_flow_name": "WARNING",
    "orphan_flow": "WARNING",
    "flow_limit_exceeded": "ERROR",
    "build_failure": "ERROR",
}

# -------------------------
# Helper Functions
# -------------------------

def get_current_git_branch() -> str:
    """
    Fetch the current Git branch name using `git rev-parse --abbrev-ref HEAD`.
    Returns 'Unknown' if unable to determine (not a git repo, git not installed, timeout, etc.).
    """
    try:
        result = subprocess.run(
            ['git', 'rev-parse', '--abbrev-ref', 'HEAD'],
            capture_output=True, text=True, check=True, timeout=5
        )
        return result.stdout.strip()
    except (subprocess.CalledProcessError, FileNotFoundError, subprocess.TimeoutExpired):
        return "Unknown"

def _format_data_to_html(data: Any, headers: Union[str, List[str]] = "firstrow") -> str:
    """
    Converts Python data structures into HTML.

    Supports:
    - List of lists -> HTML table
    - List of strings -> HTML unordered list
    - Dictionary -> HTML key-value table
    - String/int/other -> wrapped in <p>
    - Empty data -> <p>No data available</p>
    """
    if not data:
        return "<p>No data available.</p>"

    # List handling
    if isinstance(data, list):
        if all(isinstance(item, list) for item in data):
            return tabulate(data, headers=headers, tablefmt='html')
        elif all(isinstance(item, str) for item in data):
            return "<ul>" + "".join(f"<li>{item}</li>" for item in data) + "</ul>"
        else:
            return "<ul>" + "".join(f"<li>{str(item)}</li>" for item in data) + "</ul>"

    # Dictionary handling
    if isinstance(data, dict):
        table_rows = "".join(f"<tr><td>{key}</td><td>{str(value)}</td></tr>" for key, value in data.items())
        return f'<table class="table"><thead><tr><th>Key</th><th>Value</th></tr></thead><tbody>{table_rows}</tbody></table>'

    # String or other types
    return f"<p>{str(data)}</p>"

def _format_orphan_results(orphan_results: Dict[str, Any]) -> str:
    """
    Formats orphan checker results into readable HTML.
    """
    if not orphan_results:
        return "<p>No orphan issues found.</p>"

    html = ""

    # Summary
    summary = orphan_results.get("summary", {})
    if summary:
        html += "<h4>Summary</h4>"
        html += "<table class='table'><thead><tr><th>Metric</th><th>Value</th></tr></thead><tbody>"
        for key, value in summary.items():
            display_key = key.replace('_', ' ').title()
            html += f"<tr><td>{display_key}</td><td>{value}</td></tr>"
        html += "</tbody></table>"

    # Orphaned Items
    orphans = orphan_results.get("orphans", {})
    if orphans:
        html += "<h4>Orphaned Items</h4>"
        for category, items in orphans.items():
            if items:
                display_category = category.replace('_', ' ').title()
                html += f"<h5>{display_category}</h5>"
                html += "<ul>"
                for item in items:
                    if isinstance(item, tuple) and len(item) == 2:
                        html += f"<li><strong>{item[0]}</strong> (in {item[1]})</li>"
                    else:
                        html += f"<li>{item}</li>"
                html += "</ul>"

    # Validation Errors
    validation_errors = orphan_results.get("validation_errors", [])
    if validation_errors:
        html += "<h4>Validation Errors</h4>"
        html += "<ul>"
        for error in validation_errors:
            html += f"<li>{error}</li>"
        html += "</ul>"

    return html

# -------------------------
# Main Report Generation
# -------------------------

def generate_html_report(all_results: Dict[str, Any], template_string: str) -> str:
    """
    Generates an HTML report by replacing placeholders in the template string
    with validation results.

    Supports:
    - Threshold warnings
    - Scorecard metrics
    - Code review issues
    - YAML validation
    - Dependency validation
    - Flow validation
    - API validation
    - Secure properties check
    - Logging validation
    - Orphan checker results
    - Git branch and timestamps
    """

    html_content = template_string

    # -------------------------
    # 1. Threshold Warnings
    # -------------------------
    thresholds = all_results.get("thresholds", {})
    threshold_warnings = []

    max_build_size = thresholds.get("max_build_size_mb", 100)
    max_flows = thresholds.get("max_flows", 100)
    max_sub_flows = thresholds.get("max_sub_flows", 50)
    max_components = thresholds.get("max_components", 500)

    # Check build size
    build_size_mb = all_results.get("dependency_validation", {}).get("build_size_mb", 0)
    if build_size_mb > max_build_size:
        threshold_warnings.append(f"Build size {build_size_mb} MB exceeds maximum allowed {max_build_size} MB.")

    # Check flow, sub-flow, and component counts
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

    # Render threshold warnings
    if threshold_warnings:
        warnings_html = "<ul>" + "".join(f"<li><span class='badge warning'>WARNING</span> {msg}</li>" for msg in threshold_warnings) + "</ul>"
        html_content = html_content.replace("{{threshold_warnings}}", warnings_html)
    else:
        html_content = html_content.replace("{{threshold_warnings}}", "<p>No threshold warnings.</p>")

    # -------------------------
    # 2. Scorecard Table
    # -------------------------
    scorecard = all_results.get("scorecard", [])
    if scorecard:
        scorecard_rows = "".join(
            f"<tr><td>{item['metric']}</td><td>{item['value']}</td>"
            f"<td><span class='badge {item['status'].lower()}'>{item['status']}</span></td></tr>"
            for item in scorecard
        )
        html_content = html_content.replace("{{scorecard_table}}", scorecard_rows)
    else:
        html_content = html_content.replace("{{scorecard_table}}", "<tr><td colspan='3'>No scorecard data available.</td></tr>")

    # -------------------------
    # 3. Code Review Issues
    # -------------------------
    code_review_issues = all_results.get('code_reviewer_issues')
    if code_review_issues:
        code_review_table = tabulate(code_review_issues, headers=["File Name", "Status", "Issue"], tablefmt='html')
        code_review_table = code_review_table.replace('<td>WARNING</td>', '<td><span class="badge warning">WARNING</span></td>')
        code_review_table = code_review_table.replace('<td>ERROR</td>', '<td><span class="badge error">ERROR</span></td>')
        html_content = html_content.replace('{{code_review_issues_table}}', code_review_table)
    else:
        html_content = html_content.replace('{{code_review_issues_table}}', "<p>No code review issues found.</p>")

    # -------------------------
    # 4. YAML Validation
    # -------------------------
    yaml_results = all_results.get('yaml_validation')
    if yaml_results:
        yaml_table = _format_data_to_html(yaml_results) if isinstance(yaml_results, dict) else tabulate(yaml_results, headers="keys", tablefmt='html')
        html_content = html_content.replace('{{yaml_validation_results_table}}', yaml_table)
    else:
        html_content = html_content.replace('{{yaml_validation_results_table}}', "<p>No YAML validation results found.</p>")

    # -------------------------
    # 5. Dependency Validation
    # -------------------------
    dependency_results = all_results.get('dependency_validation')
    dep_tables = []
    has_dep_issues = False
    if isinstance(dependency_results, dict) and dependency_results:
        for pom_path, dep_info in dependency_results.items():
            if pom_path == "build_size_mb":
                continue
            rows = []
            for category in ["missing_jars", "unresolved_dependencies", "duplicate_dependencies"]:
                if dep_info.get(category):
                    for item in dep_info[category]:
                        type_label = category.replace("_", " ").title()
                        rows.append([type_label, item])
            if rows:
                has_dep_issues = True
                dep_tables.append(f"<h4>{pom_path}</h4>{tabulate(rows, headers=['Type', 'Value'], tablefmt='html')}")
        html_content = html_content.replace('{{dependency_validation_results_table}}', "".join(dep_tables) if has_dep_issues else "<p>No dependency issues found.</p>")
    else:
        html_content = html_content.replace('{{dependency_validation_results_table}}', "<p>No dependency issues found.</p>")

    # -------------------------
    # 6. Flow Validation Results
    # -------------------------
    flow_results = all_results.get('flow_validation')
    if isinstance(flow_results, list) and flow_results and all(isinstance(item, dict) for item in flow_results):
        headers = list(flow_results[0].keys())
        table_data = [[item.get(h, '') for h in headers] for item in flow_results]
        html_content = html_content.replace('{{flow_validation_results_table}}', tabulate(table_data, headers=headers, tablefmt='html'))
    elif flow_results:
        html_content = html_content.replace('{{flow_validation_results_table}}', _format_data_to_html(flow_results))
    else:
        html_content = html_content.replace('{{flow_validation_results_table}}', "<p>No flow validation issues found.</p>")

    # -------------------------
    # 7. API Validation Results
    # -------------------------
    api_results = all_results.get('api_validation')
    if isinstance(api_results, list) and api_results and all(isinstance(item, dict) for item in api_results):
        headers = list(api_results[0].keys())
        table_data = [[item.get(h, '') for h in headers] for item in api_results]
        html_content = html_content.replace('{{api_validation_results_table}}', tabulate(table_data, headers=headers, tablefmt='html'))
    elif api_results:
        html_content = html_content.replace('{{api_validation_results_table}}', _format_data_to_html(api_results))
    else:
        html_content = html_content.replace('{{api_validation_results_table}}', "<p>No API validation issues found.</p>")

    # -------------------------
    # 8. Mule Secure Properties
    # -------------------------
    secure_props_status = all_results.get('project_uses_secure_properties')
    html_content = html_content.replace('{{secure_properties_status}}',
                                        f"<p>{secure_props_status}</p>" if secure_props_status is not None else "<p>No secure properties validation result.</p>")

    # -------------------------
    # 9. Logging Validation Results
    # -------------------------
    logging_results = all_results.get('logging_validation')
    if isinstance(logging_results, dict) and (logging_results.get("logger_issues") or logging_results.get("log4j_warnings")):
        log_html = ""
        if logging_results.get("logger_issues"):
            log_html += "<h4>Logger Issues</h4>" + _format_data_to_html(logging_results["logger_issues"])
        if logging_results.get("log4j_warnings"):
            log_html += "<h4>Log4j Warnings</h4>" + _format_data_to_html(logging_results["log4j_warnings"])
        html_content = html_content.replace('{{logging_validation_results_table}}', log_html)
    else:
        html_content = html_content.replace('{{logging_validation_results_table}}', "<p>No logging issues found.</p>")

    # -------------------------
    # 10. Orphan Checker Results
    # -------------------------
    orphan_results = all_results.get("orphan_checker")
    html_content = html_content.replace('{{orphan_validation_results_table}}',
                                        _format_data_to_html(orphan_results) if orphan_results else "<p>No orphan issues found.</p>")

    # -------------------------
    # 11. Fallbacks for missing placeholders
    # -------------------------
    placeholders = [
        'code_review_issues_table', 'yaml_validation_results_table',
        'dependency_validation_results_table', 'flow_validation_results_table',
        'api_validation_results_table', 'secure_properties_status',
        'logging_validation_results_table', 'orphan_validation_results_table'
    ]
    for ph in placeholders:
        if f'{{{{{ph}}}}}' in html_content:
            html_content = html_content.replace(f'{{{{{ph}}}}}', "<p>Data not available.</p>")

    # -------------------------
    # 12. Git Branch & Timestamps
    # -------------------------
    branch_name = all_results.get('git_branch_name') or all_results.get('git_branch') or get_current_git_branch()
    html_content = html_content.replace('{{git_branch_name}}', branch_name)

    # Add report start and end time
    html_content = html_content.replace('{{report_start_time}}', all_results.get('report_start_time', 'N/A'))
    html_content = html_content.replace('{{report_end_time}}', all_results.get('report_end_time', 'N/A'))
    html_content = html_content.replace('{{report_duration}}', all_results.get('report_duration', 'N/A'))

    # Summary banner placeholders
    status = all_results.get('status', 'Unknown')
    html_content = html_content.replace('{{ status }}', status)
    html_content = html_content.replace('{{ status|lower }}', status.lower())
    html_content = html_content.replace('{{ project_name }}', all_results.get('project_name', 'Unknown'))
    html_content = html_content.replace('{{ git_branch }}', all_results.get('git_branch', 'Unknown'))
    html_content = html_content.replace('{{ timestamp }}', all_results.get('timestamp', 'Unknown'))
    html_content = html_content.replace('{{ python_version }}', all_results.get('python_version', 'Unknown'))

    return html_content
