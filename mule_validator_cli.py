#!/usr/bin/env python
"""
Mule Validator CLI
==================
"""

import os
import sys
import argparse
import logging
from datetime import datetime
from mule_validator import api_validator, html_reporter
from mule_validator.html_reporter import generate_orphan_report_page

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
    return os.path.abspath(os.path.expanduser(path))

def load_template(template_path: str) -> str:
    if not os.path.isfile(template_path):
        script_dir = os.path.dirname(os.path.abspath(__file__))
        alt_path = os.path.join(script_dir, template_path)
        if os.path.isfile(alt_path):
            template_path = alt_path
        else:
            raise FileNotFoundError(f"Template file not found: {template_path}")
    with open(template_path, "r", encoding="utf-8") as f:
        return f.read()

def save_report(output_path: str, html_content: str):
    os.makedirs(os.path.dirname(output_path), exist_ok=True)
    with open(output_path, "w", encoding="utf-8") as f:
        f.write(html_content)
    logger.info(f"Report saved to: {output_path}")

def get_git_branch(project_path: str) -> str:
    """
    Determine the current git branch of the project.
    """
    git_head_path = os.path.join(project_path, ".git", "HEAD")
    if os.path.isfile(git_head_path):
        try:
            with open(git_head_path, "r") as f:
                ref_line = f.readline().strip()
                if ref_line.startswith("ref:"):
                    return ref_line.split("/")[-1]
        except Exception as e:
            logger.warning(f"Unable to read git branch from HEAD: {e}")

    return html_reporter.get_current_git_branch()

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
    # 2. Prepare results dictionary
    # -------------------------
    now = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    git_branch = get_git_branch(project_path)

    all_results = {
        "project_name": os.path.basename(project_path),
        "status": "PASS" if not api_results["notes"] else "WARN",
        "git_branch_name": git_branch,
        "git_branch": git_branch,
        "report_start_time": now,
        "report_end_time": now,
        "report_duration": "N/A",
        "timestamp": now,
        "python_version": f"{sys.version_info.major}.{sys.version_info.minor}.{sys.version_info.micro}",
        "scorecard": [
            {
                "metric": "API Spec Found",
                "value": "Yes" if api_results["api_spec_zip_found"] else "No",
                "status": "PASS" if api_results["api_spec_zip_found"] else "FAIL"
            },
            {
                "metric": "APIkit Router Found",
                "value": api_results["apikit_router_file"] or "N/A",
                "status": "PASS" if api_results["apikit_router_found"] else "FAIL"
            },
        ],
        "orphan_checker": api_results.get("orphan_checker", {}),
        "notes": api_results["notes"],
    }

    # -------------------------
    # 3. Generate main HTML report
    # -------------------------
    template_string = load_template(template_path)
    html_report = html_reporter.generate_html_report(all_results, template_string)

    # -------------------------
    # 4. Save main report
    # -------------------------
    save_report(output_path, html_report)

    # -------------------------
    # 5. OPTIONAL: Save standalone orphan report (FULL HTML PAGE)
    # -------------------------
    orphan_results = all_results.get("orphan_checker",{})

    orphan_html = generate_orphan_report_page(
            orphan_results,
            project_name=all_results["project_name"]
        )

    orphan_report_path = os.path.join(
            os.path.dirname(output_path),
            "orphan_report.html"
        )

    save_report(orphan_report_path, orphan_html)

    logger.info("Mule Validator CLI execution completed successfully!")

# -------------------------
# Entry point
# -------------------------
if __name__ == "__main__":
    main()
