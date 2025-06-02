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
    except (subprocess.CalledProcessError, FileNotFoundError, subprocess.TimeoutExpired):
        return "Unknown"

def _format_data_to_html(data, headers="firstrow"):
    """
    Helper function to format various data structures to HTML.
    """
    if not data:
        return "<p>No data available.</p>"

    if isinstance(data, list):
        if not data:
            return "<p>No data available.</p>"
        if all(isinstance(item, list) for item in data):
            return tabulate(data, headers=headers, tablefmt='html')
        elif all(isinstance(item, str) for item in data):
            items_html = "".join(f"<li>{item}</li>" for item in data)
            return f"<ul>{items_html}</ul>"
        else:
            items_html = "".join(f"<li>{str(item)}</li>" for item in data)
            return f"<ul>{items_html}</ul>"
    elif isinstance(data, dict):
        if not data:
            return "<p>No data available.</p>"
        table_rows = "".join(f"<tr><td>{key}</td><td>{value}</td></tr>" for key, value in data.items())
        return f"<table><thead><tr><th>Key</th><th>Value</th></tr></thead><tbody>{table_rows}</tbody></table>"
    elif isinstance(data, str):
        return f"<p>{data}</p>"
    else:
        return f"<p>{str(data)}</p>"

def generate_html_report(all_results, template_string):
    """
    Generates an HTML report by populating a template string with validation results.
    """
    html_content = template_string

    # 1. Code Review Issues
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

    # Fallback for any placeholders not explicitly handled, to avoid them showing in the report
    html_content = html_content.replace('{{code_review_issues_table}}', "<p>Data not available.</p>")
    html_content = html_content.replace('{{yaml_validation_results_table}}', "<p>Data not available.</p>")
    html_content = html_content.replace('{{dependency_validation_results_table}}', "<p>Data not available.</p>")
    html_content = html_content.replace('{{flow_validation_results_table}}', "<p>Data not available.</p>")
    html_content = html_content.replace('{{api_validation_results_table}}', "<p>Data not available.</p>")
    html_content = html_content.replace('{{secure_properties_status}}', "<p>Data not available.</p>")
    html_content = html_content.replace('{{logging_validation_results_table}}', "<p>Data not available.</p>")

    # Add Git branch name
    branch_name = all_results.get('git_branch_name', 'Unknown')
    html_content = html_content.replace('{{git_branch_name}}', branch_name)
    
    # Add report start and end time
    html_content = html_content.replace('{{report_start_time}}', all_results.get('report_start_time', 'N/A'))
    html_content = html_content.replace('{{report_end_time}}', all_results.get('report_end_time', 'N/A'))
    html_content = html_content.replace('{{report_duration}}', all_results.get('report_duration', 'N/A'))

    return html_content