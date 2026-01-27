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

    if isinstance(data, list):
        if all(isinstance(item, list) for item in data):
            return tabulate(data, headers=headers, tablefmt='html')
        elif all(isinstance(item, str) for item in data):
            return "<ul>" + "".join(f"<li>{item}</li>" for item in data) + "</ul>"
        else:
            return "<ul>" + "".join(f"<li>{str(item)}</li>" for item in data) + "</ul>"

    if isinstance(data, dict):
        table_rows = "".join(f"<tr><td>{key}</td><td>{str(value)}</td></tr>" for key, value in data.items())
        return f'<table class="table"><thead><tr><th>Key</th><th>Value</th></tr></thead><tbody>{table_rows}</tbody></table>'

    return f"<p>{str(data)}</p>"

def _format_orphan_results(orphan_results: Dict[str, Any]) -> str:
    """
    Formats orphan checker results into readable HTML with collapsible details.
    """
    if not orphan_results:
        return "<p>No orphan issues found.</p>"

    html = ""

    # --- Summary
    summary = orphan_results.get("summary", {})
    if summary:
        html += "<h3>Summary</h3><ul>"
        for key, value in summary.items():
            display_key = key.replace("_", " ").title()
            html += f"<li><strong>{display_key}:</strong> {value}</li>"
        html += "</ul>"

    # --- Orphans by category
    orphans = orphan_results.get("orphans", {})
    if orphans:
        html += "<h3>🛑 Orphan Items</h3>"
        for category, items in orphans.items():
            if not items:  # Skip empty categories
                continue
                
            display_category = category.replace('_', ' ').title()
            html += f"<details><summary><strong>{display_category} ({len(items)})</strong></summary><ul>"
            
            # Handle different item structures
            for item in items:
                if category in ['flows', 'subflows']:
                    # These are tuples: (name, file_path)
                    if isinstance(item, (tuple, list)) and len(item) >= 2:
                        name, file_path = item[0], item[1]
                        html += f"<li><code class='orphan'>{name}</code> — <small>{file_path}</small></li>"
                    else:
                        html += f"<li><code class='orphan'>{item}</code></li>"
                elif category == 'variables':
                    # Variables are tuples: (var_name, flow_name, file_path)
                    if isinstance(item, (tuple, list)) and len(item) >= 3:
                        var_name, flow_name, file_path = item[0], item[1], item[2]
                        html += f"<li><code class='orphan'>{var_name}</code> — <small>Flow: {flow_name}, File: {file_path}</small></li>"
                    else:
                        html += f"<li><code class='orphan'>{item}</code></li>"
                else:
                    # Simple strings or other items
                    html += f"<li><code class='orphan'>{item}</code></li>"
            
            html += "</ul></details>"

    # --- Used items (collapsed by default for brevity)
    used_items = orphan_results.get("used", {})
    if used_items:
        html += "<h3>✅ Used Items</h3>"
        for category, items in used_items.items():
            if not items:  # Skip empty categories
                continue
                
            display_category = category.replace('_', ' ').title()
            html += f"<details><summary><strong>{display_category} ({len(items)})</strong></summary><ul>"
            
            for item in items:
                if category in ['flows', 'subflows']:
                    if isinstance(item, (tuple, list)) and len(item) >= 2:
                        name, file_path = item[0], item[1]
                        html += f"<li><code class='used'>{name}</code> — <small>{file_path}</small></li>"
                    else:
                        html += f"<li><code class='used'>{item}</code></li>"
                elif category == 'variables':
                    if isinstance(item, (tuple, list)) and len(item) >= 3:
                        var_name, flow_name, file_path = item[0], item[1], item[2]
                        html += f"<li><code class='used'>{var_name}</code> — <small>Flow: {flow_name}, File: {file_path}</small></li>"
                    else:
                        html += f"<li><code class='used'>{item}</code></li>"
                else:
                    html += f"<li><code class='used'>{item}</code></li>"
            
            html += "</ul></details>"

    # --- Declared items (collapsed by default)
    declared_items = orphan_results.get("declared", {})
    if declared_items:
        html += "<h3>📦 Declared Items</h3>"
        for category, items in declared_items.items():
            if not items:  # Skip empty categories
                continue
                
            display_category = category.replace('_', ' ').title()
            html += f"<details><summary><strong>{display_category} ({len(items)})</strong></summary><ul>"
            
            for item in items:
                if category == 'subflows':
                    if isinstance(item, (tuple, list)) and len(item) >= 2:
                        name, file_path = item[0], item[1]
                        html += f"<li><code class='declared'>{name}</code> — <small>{file_path}</small></li>"
                    else:
                        html += f"<li><code class='declared'>{item}</code></li>"
                elif category == 'variables':
                    if isinstance(item, (tuple, list)) and len(item) >= 3:
                        var_name, flow_name, file_path = item[0], item[1], item[2]
                        html += f"<li><code class='declared'>{var_name}</code> — <small>Flow: {flow_name}, File: {file_path}</small></li>"
                    else:
                        html += f"<li><code class='declared'>{item}</code></li>"
                else:
                    html += f"<li><code class='declared'>{item}</code></li>"
            
            html += "</ul></details>"

    # --- Validation errors
    validation_errors = orphan_results.get("validation_errors", [])
    if validation_errors:
        html += "<h4>⚠️ Validation Warnings</h4><ul>"
        for error in validation_errors[:10]:  # Show first 10
            html += f"<li><small>{error}</small></li>"
        if len(validation_errors) > 10:
            html += f"<li><em>...and {len(validation_errors) - 10} more warnings</em></li>"
        html += "</ul>"

    return html

def generate_orphan_report_page(orphan_results: Dict[str, Any], project_name: str = "MuleSoft Project") -> str:
    """
    Wraps orphan results into a full standalone HTML page.
    """
    orphan_html_content = _format_orphan_results(orphan_results)

    html_page = f"""<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <title>Orphan Flow Report - {project_name}</title>
    <style>
        body {{ font-family: Arial, sans-serif; margin: 20px; }}
        table {{ border-collapse: collapse; width: 100%; margin-bottom: 20px; }}
        th, td {{ border: 1px solid #ccc; padding: 8px; text-align: left; }}
        th {{ background-color: #f2f2f2; }}
        ul {{ list-style-type: disc; padding-left: 20px; }}
        h4, h5 {{ margin-top: 20px; }}
    </style>
</head>
<body>
    <h2>Orphan Flow Report - {project_name}</h2>
    {orphan_html_content}
</body>
</html>"""
    return html_page


def _format_threshold_warnings(threshold_warnings: List[str]) -> str:
    if not threshold_warnings:
        return "<p>No threshold warnings available.</p>"

    html = "<ul>"
    for warning in threshold_warnings:
        html += f"<li>{warning}</li>"
    html += "</ul>"
    return html


# -------------------------
# Main Report Generation
# -------------------------

def generate_html_report(all_results: Dict[str, Any], template_string: str) -> str:
    """
    Generates an HTML report by replacing placeholders in the template string
    with validation results.
    """
    html_content = template_string

    # -- Scorecard
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

    # -- Other placeholders remain the same as before
    # (code_review_issues_table, yaml_validation_results_table, dependency_validation_results_table,
    # flow_validation_results_table, api_validation_results_table, secure_properties_status,
    # logging_validation_results_table, orphan_validation_results_table, git_branch_name, etc.)

    # Keep existing logic for orphan checker inside main report:
    orphan_results = all_results.get("orphan_checker")
    html_content = html_content.replace('{{orphan_validation_results_table}}',
                                        _format_orphan_results(orphan_results) if orphan_results else "<p>No orphan issues found.</p>")

    # Fill in Git branch and timestamps
    branch_name = all_results.get('git_branch_name') or all_results.get('git_branch') or get_current_git_branch()
    html_content = html_content.replace('{{git_branch_name}}', branch_name)
    git_branch = all_results.get('git_branch', 'Unknown')
    html_content = html_content.replace('{{git_branch}}', git_branch)
    html_content = html_content.replace('{{ git_branch }}', git_branch)
    html_content = html_content.replace('{{report_start_time}}', all_results.get('report_start_time', 'N/A'))
    html_content = html_content.replace('{{report_end_time}}', all_results.get('report_end_time', 'N/A'))
    html_content = html_content.replace('{{report_duration}}', all_results.get('report_duration', 'N/A'))
    html_content = html_content.replace('{{ status }}', all_results.get('status', 'Unknown'))
    html_content = html_content.replace('{{ status|lower }}', all_results.get('status', 'Unknown').lower())
    html_content = html_content.replace('{{ project_name }}', all_results.get('project_name', 'Unknown'))
    html_content = html_content.replace('{{ timestamp }}', all_results.get('timestamp', 'Unknown'))
    html_content = html_content.replace('{{ python_version }}', all_results.get('python_version', 'Unknown'))
    # -------------------------
    # Fallback replacements for unimplemented sections
    # -------------------------
    # -------------------------
    # Code Review Issues
    # -------------------------
    code_review_issues = all_results.get('code_reviewer_issues')
    if code_review_issues and len(code_review_issues) > 0:
        html_content = html_content.replace(
            "{{code_review_issues_table}}",
            _format_data_to_html(code_review_issues, headers=["File", "Severity", "Issue"])
        )

    # -------------------------
    # YAML Validation
    # -------------------------
    yaml_validation = all_results.get('yaml_validation')
    if yaml_validation and len(yaml_validation) > 0:
        if isinstance(yaml_validation, list) and isinstance(yaml_validation[0], dict):
            yaml_as_lists = [[item.get('file', item.get('item', 'Unknown')), 
                            item.get('error_type', 'Unknown'), 
                            item.get('details', item.get('message', ''))] 
                            for item in yaml_validation]
            html_content = html_content.replace(
                "{{yaml_validation_results_table}}",
                _format_data_to_html(yaml_as_lists, headers=["File/Item", "Error Type", "Details"])
            )
        elif isinstance(yaml_validation, list):
            # List but not dicts - use as is
            html_content = html_content.replace(
                "{{yaml_validation_results_table}}",
                _format_data_to_html(yaml_validation, headers=["File/Item", "Error Type", "Details"])
            )
        else:
            # It's a dict or other type - convert to message
            html_content = html_content.replace(
                "{{yaml_validation_results_table}}",
                f"<p>{str(yaml_validation)}</p>"
            )

    # -------------------------
    # Dependency Validation
    # -------------------------
    dependency_validation = all_results.get('dependency_validation')
    if dependency_validation and isinstance(dependency_validation, dict):
        dep_html = "<h4>Dependency Analysis by POM File</h4>"
        for pom_file, dep_data in dependency_validation.items():
            if isinstance(dep_data, dict):
                dep_html += f"<h5>{pom_file}</h5><ul>"
                
                missing = dep_data.get('missing_jars', [])
                if missing:
                    dep_html += f"<li><strong>Missing JARs ({len(missing)}):</strong><ul>"
                    for jar in missing[:5]:
                        dep_html += f"<li><code>{jar}</code></li>"
                    if len(missing) > 5:
                        dep_html += f"<li><em>...and {len(missing) - 5} more</em></li>"
                    dep_html += "</ul></li>"
                
                unresolved = dep_data.get('unresolved_dependencies', [])
                if unresolved:
                    dep_html += f"<li><strong>Unresolved Dependencies ({len(unresolved)}):</strong><ul>"
                    for dep in unresolved[:5]:
                        dep_html += f"<li><code>{dep}</code></li>"
                    if len(unresolved) > 5:
                        dep_html += f"<li><em>...and {len(unresolved) - 5} more</em></li>"
                    dep_html += "</ul></li>"
                
                duplicates = dep_data.get('duplicate_dependencies', [])
                if duplicates:
                    dep_html += f"<li><strong>Duplicate Dependencies ({len(duplicates)}):</strong><ul>"
                    for dup in duplicates:
                        dep_html += f"<li><code>{dup}</code></li>"
                    dep_html += "</ul></li>"
                
                all_deps = dep_data.get('all_dependencies', [])
                dep_html += f"<li><strong>Total Dependencies:</strong> {len(all_deps)}</li>"
                dep_html += "</ul>"
        
        html_content = html_content.replace("{{dependency_validation_results_table}}", dep_html)

    # -------------------------
    # Flow Validation
    # -------------------------
    flow_validation = all_results.get('flow_validation')
    if flow_validation and isinstance(flow_validation, dict):
        flow_html = "<h4>Flow Analysis Summary</h4><ul>"
        
        total_counts = flow_validation.get('total_counts', {})
        flow_html += f"<li><strong>Total Flows:</strong> {total_counts.get('flows', 0)}</li>"
        flow_html += f"<li><strong>Total Sub-Flows:</strong> {total_counts.get('sub_flows', 0)}</li>"
        flow_html += f"<li><strong>Total Components:</strong> {total_counts.get('components', 0)}</li>"
        
        flows_ok = flow_validation.get('flows_ok', True)
        sub_flows_ok = flow_validation.get('sub_flows_ok', True)
        components_ok = flow_validation.get('components_ok', True)
        naming_ok = flow_validation.get('flow_names_camel_case_ok', True)
        
        flow_html += f"<li><strong>Flows within limit:</strong> <span class='badge {'pass' if flows_ok else 'warn'}'>{'✓' if flows_ok else '✗'}</span></li>"
        flow_html += f"<li><strong>Sub-flows within limit:</strong> <span class='badge {'pass' if sub_flows_ok else 'warn'}'>{'✓' if sub_flows_ok else '✗'}</span></li>"
        flow_html += f"<li><strong>Components within limit:</strong> <span class='badge {'pass' if components_ok else 'warn'}'>{'✓' if components_ok else '✗'}</span></li>"
        flow_html += f"<li><strong>Naming conventions:</strong> <span class='badge {'pass' if naming_ok else 'warn'}'>{'✓' if naming_ok else '✗'}</span></li>"
        
        invalid_names = flow_validation.get('invalid_flow_names', [])
        if invalid_names:
            flow_html += f"<li><strong>Invalid Flow Names ({len(invalid_names)}):</strong><ul>"
            for name in invalid_names:
                flow_html += f"<li><code>{name}</code></li>"
            flow_html += "</ul></li>"
        
        flow_html += "</ul>"
        html_content = html_content.replace("{{flow_validation_results_table}}", flow_html)

    # -------------------------
    # API Validation
    # -------------------------
    api_validation = all_results.get('api_validation')
    if api_validation:
        # Check if it's a dict (real CLI data) or list (test mock data)
        if isinstance(api_validation, dict):
            api_html = "<ul>"
            api_html += f"<li><strong>API Spec Dependency:</strong> {api_validation.get('api_spec_dependency', 'Not found')}</li>"
            api_html += f"<li><strong>API Spec ZIP Found:</strong> <span class='badge {'pass' if api_validation.get('api_spec_zip_found') else 'error'}'>{'Yes' if api_validation.get('api_spec_zip_found') else 'No'}</span></li>"
            api_html += f"<li><strong>APIkit Router Found:</strong> <span class='badge {'pass' if api_validation.get('apikit_router_found') else 'error'}'>{'Yes' if api_validation.get('apikit_router_found') else 'No'}</span></li>"
            
            if api_validation.get('apikit_router_file'):
                api_html += f"<li><strong>APIkit Router File:</strong> <code>{api_validation.get('apikit_router_file')}</code></li>"
            
            notes = api_validation.get('notes', [])
            if notes:
                api_html += "<li><strong>Notes:</strong><ul>"
                for note in notes:
                    api_html += f"<li>{note}</li>"
                api_html += "</ul></li>"
            
            api_html += "</ul>"
            html_content = html_content.replace("{{api_validation_results_table}}", api_html)
        elif isinstance(api_validation, list):
            # Test data - list of dicts, display as table
            html_content = html_content.replace(
                "{{api_validation_results_table}}",
                _format_data_to_html(api_validation, headers="firstrow")
            )

    # -- Components validation
    components_validation = all_results.get('components_validator')
    if components_validation:
        html_content = html_content.replace(
            "{{components_validation_results_table}}",
            _format_data_to_html(components_validation)
        )

    # -- Secure properties (True/False)
    secure_properties = all_results.get('project_uses_secure_properties')
    if secure_properties is not None:
        html_content = html_content.replace(
            "{{secure_properties_status}}",
            f"<p>{secure_properties}</p>"
        )
    
    # -------------------------
    # Logging Validation
    # -------------------------
    logging_validation = all_results.get('logging_validation')
    logs_html = ""

    if logging_validation and isinstance(logging_validation, dict):
        logger_issues = logging_validation.get("logger_issues", [])
        if logger_issues:
            logs_html += "<h4>Logger Issues</h4>"            
            # to verify first item is a dict before treating all as dicts
            if isinstance(logger_issues[0], dict):
                logs_html += "<table><thead><tr><th>File</th><th>Flow</th><th>Loggers</th><th>Issues</th></tr></thead><tbody>"
                for issue in logger_issues:
                    issues_list = []
                    if issue.get('has_too_many_loggers'):
                        issues_list.append(f"Too many loggers ({issue.get('logger_count')})")
                    if issue.get('has_debug'):
                        issues_list.append(f"DEBUG level used ({issue.get('debug_count')} times)")
                    if issue.get('error_outside_exception'):
                        issues_list.append("ERROR logged outside exception handler")
                    
                    issues_str = ", ".join(issues_list) if issues_list else "No issues"
                    logs_html += f"<tr><td><code>{issue.get('file')}</code></td><td><code>{issue.get('flow')}</code></td><td>{issue.get('logger_count')}</td><td>{issues_str}</td></tr>"
                logs_html += "</tbody></table>"
            else:
                # Test/mock data - display as simple list
                logs_html += "<ul>"
                for issue in logger_issues:
                    logs_html += f"<li>{str(issue)}</li>"
                logs_html += "</ul>"
        
        log4j_warnings = logging_validation.get("log4j_warnings", [])
        if log4j_warnings:
            logs_html += "<h4>Log4j Configuration Warnings</h4><ul>"
            for warning in log4j_warnings:
                logs_html += f"<li>{warning}</li>"
            logs_html += "</ul>"

    if not logs_html:
        logs_html = "<p>No logging issues detected.</p>"

    html_content = html_content.replace("{{logging_validation_results_table}}", logs_html)

    # -------------------------
    # Threshold warnings
    # -------------------------
    threshold_warnings = []

    # Explicit threshold warnings (if provided)
    explicit_thresholds = all_results.get("threshold_warnings", [])
    if explicit_thresholds:
        threshold_warnings.extend(explicit_thresholds)

    # Auto-generate build size warning
    dependency_validation = all_results.get("dependency_validation", {})
    if isinstance(dependency_validation, dict):
        build_size = dependency_validation.get("build_size_mb")
        if isinstance(build_size, (int, float)) and build_size > 100:
            threshold_warnings.append(
                f"Build size exceeds threshold: {build_size} MB"
            )

    html_content = html_content.replace(
        "{{threshold_warnings}}",
        _format_threshold_warnings(threshold_warnings)
    )

    # Fallback if nothing to display
    if not logs_html:
        logs_html = "<p>No logging issues detected.</p>"

    # Replace placeholder
    html_content = html_content.replace("{{logging_validation_results_table}}", logs_html)

    # -- Fallbacks for any remaining placeholders
    fallbacks = {
        
        "{{code_review_issues_table}}": "<p>No code review issues detected.</p>",
        "{{yaml_validation_results_table}}": "<p>No YAML validation issues found.</p>",
        "{{dependency_validation_results_table}}": "<p>No dependency issues found.</p>",
        "{{flow_validation_results_table}}": "<p>No flow validation issues found.</p>",
        "{{api_validation_results_table}}": "<p>No API validation issues found.</p>",
        "{{components_validation_results_table}}": "<p>Data not available.</p>",
        "{{secure_properties_status}}": f"<p>{all_results.get('project_uses_secure_properties', 'Not evaluated')}</p>",
        "{{logging_validation_results_table}}": "<p>No logging issues detected.</p>",
    }

    for placeholder, replacement in fallbacks.items():
        html_content = html_content.replace(placeholder, replacement)

    return html_content