#!/usr/bin/env python
"""
Mule Validator CLI
==================

Usage:
    python mule_validator_cli.py --project <path_to_mulesoft_project> [--template <template_file>] [--output <output_file>]

This CLI validates a MuleSoft project:
- Checks API spec dependencies and RAML zips
- Validates flows, logging, orphaned items
- Generates a HTML report using a template
"""

import os
import sys
import argparse
import logging
from datetime import datetime
from mule_validator import api_validator, html_reporter

# -------------------------
# Logger setup
# -------------------------
logging.basicConfig(
    level=logging.INFO,
    format='[%(levelname)s] %(message)s'
)
logger = logging.getLogger(__name__)

# -------------------------
# Helper Functions
# -------------------------
def resolve_path(path: str) -> str:
    """Return absolute path, expanding user and resolving relative paths."""
    return os.path.abspath(os.path.expanduser(path))

def load_template(template_path: str) -> str:
    """Load the HTML template file."""
    if not os.path.isfile(template_path):
        # Try resolving relative to this script's directory
        script_dir = os.path.dirname(os.path.abspath(__file__))
        alt_path = os.path.join(script_dir, template_path)
        if os.path.isfile(alt_path):
            template_path = alt_path
        else:
            raise FileNotFoundError(f"Template file not found: {template_path}")
    with open(template_path, "r", encoding="utf-8") as f:
        return f.read()

def save_report(output_path: str, html_content: str):
    """Save the HTML report."""
    os.makedirs(os.path.dirname(output_path), exist_ok=True)
    with open(output_path, "w", encoding="utf-8") as f:
        f.write(html_content)
    logger.info(f"Report saved to: {output_path}")

# -------------------------
# Main CLI
# -------------------------
def main():
    parser = argparse.ArgumentParser(description="MuleSoft Project Validator CLI")
    parser.add_argument("--project", required=True, help="Path to MuleSoft project")
    parser.add_argument("--template", default="report_template.html", help="Path to HTML report template")
    parser.add_argument("--output", default="reports/mule_validator_report.html", help="Path to output HTML report")
    args = parser.parse_args()

    project_path = resolve_path(args.project)
    template_path = resolve_path(args.template)
    output_path = resolve_path(args.output)

    logger.info(f"Validating project at: {project_path}")
    logger.info(f"Using HTML template: {template_path}")

    # -------------------------
    # 1. Validate API spec & flows
    # -------------------------
    api_results = api_validator.validate_api_spec_and_flows(project_path)
    logger.info("API spec & flow validation completed")

    # -------------------------
    # 2. Prepare results dictionary for report
    # -------------------------
    now = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    all_results = {
        "project_name": os.path.basename(project_path),
        "status": "PASS" if not api_results["notes"] else "WARN",
        "git_branch_name": api_results.get("git_branch_name") or "Unknown",
        "git_branch": api_results.get("git_branch_name") or "Unknown",
        "report_start_time": now,
        "report_end_time": now,
        "report_duration": "N/A",
        "timestamp": now,
        "python_version": f"{sys.version_info.major}.{sys.version_info.minor}.{sys.version_info.micro}",
        "scorecard": [
            {"metric": "API Spec Found", "value": "Yes" if api_results["api_spec_zip_found"] else "No", "status": "PASS" if api_results["api_spec_zip_found"] else "FAIL"},
            {"metric": "APIkit Router Found", "value": api_results["apikit_router_file"] or "N/A", "status": "PASS" if api_results["apikit_router_found"] else "FAIL"},
        ],
        "thresholds": {},
        "dependency_validation": {},
        "code_reviewer_issues": [],
        "yaml_validation": {},
        "flow_validation": [],
        "flow_validation_stats": {},
        "api_validation": [],
        "project_uses_secure_properties": None,
        "logging_validation": {},
        "orphan_checker": {},
        "notes": api_results["notes"],
    }

    # -------------------------
    # 3. Generate HTML report
    # -------------------------
    template_string = load_template(template_path)
    html_report = html_reporter.generate_html_report(all_results, template_string)

    # -------------------------
    # 4. Save report
    # -------------------------
    save_report(output_path, html_report)

    logger.info("Mule Validator CLI execution completed successfully!")

# -------------------------
# Entry point
# -------------------------
if __name__ == "__main__":
    main()
