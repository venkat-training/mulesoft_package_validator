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
from mule_validator import (
    api_validator, 
    html_reporter,
    code_reviewer,
    configfile_validator,
    dependency_validator,
    flow_validator,
    logs_reviewer
)
from mule_validator.html_reporter import generate_orphan_report_page
from mule_validator.mule_orphan_checker import MuleComprehensiveOrphanChecker

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

def calculate_status(all_results):
    """Calculate overall validation status"""
    orphan_count = all_results.get("orphan_checker", {}).get("summary", {}).get("total_orphaned_items", 0)
    if orphan_count > 0:
        return "WARN"
    
    if all_results.get("threshold_warnings"):
        return "WARN"
    
    # Check for any validation errors
    if all_results.get("code_reviewer_issues"):
        return "WARN"
    
    return "PASS"

# -------------------------
# Main CLI
# -------------------------
def main():
    parser = argparse.ArgumentParser(description="MuleSoft Project Validator CLI")
    parser.add_argument("--project", required=True, help="Path to MuleSoft project")
    parser.add_argument("--template", default="report_template.html", help="Path to HTML report template")
    parser.add_argument("--output", default="reports/mule_validator_report.html", help="Path to output HTML report")
    parser.add_argument("--max-flows", type=int, default=100, help="Maximum allowed flows")
    parser.add_argument("--max-sub-flows", type=int, default=50, help="Maximum allowed sub-flows")
    parser.add_argument("--max-components", type=int, default=500, help="Maximum allowed components")
    parser.add_argument("--max-build-size-mb", type=int, default=100, help="Maximum build size in MB")
    args = parser.parse_args()

    project_path = resolve_path(args.project)
    template_path = resolve_path(args.template)
    output_path = resolve_path(args.output)

    logger.info(f"Validating project at: {project_path}")
    logger.info(f"Using HTML template: {template_path}")

    start_time = datetime.now()

    # -------------------------
    # 1. Code Review
    # -------------------------
    logger.info("Reviewing code and flows...")
    try:
        code_reviewer_results, project_uses_secure_properties = code_reviewer.review_all_files(project_path)        
        logger.info(f"DEBUG: Code review results count: {len(code_reviewer_results) if code_reviewer_results else 0}")
        logger.info(f"DEBUG: Code review sample: {code_reviewer_results[:2] if code_reviewer_results else 'empty'}")
    except Exception as e:
        logger.error(f"Code review failed: {e}")
        code_reviewer_results = []
        project_uses_secure_properties = False

    # -------------------------
    # 2. YAML Validation
    # -------------------------
    logger.info("Validating YAML configurations...")
    try:
        yaml_results = configfile_validator.validate_files(project_path, project_uses_secure_properties)
    except Exception as e:
        logger.error(f"YAML validation failed: {e}")
        yaml_results = []

    # -------------------------
    # 3. Dependency Validation
    # -------------------------
    logger.info("Validating dependencies and build size...")
    try:
        dependency_results = dependency_validator.validate_all_projects(project_path)
    except Exception as e:
        logger.error(f"Dependency validation failed: {e}")
        dependency_results = {}

    # -------------------------
    # 4. Flow Validation
    # -------------------------
    logger.info("Validating flows and components...")
    try:
        flow_results = flow_validator.validate_flows_in_package(
            project_path,
            max_flows=args.max_flows,
            max_sub_flows=args.max_sub_flows,
            max_components=args.max_components
        )
    except Exception as e:
        logger.error(f"Flow validation failed: {e}")
        flow_results = {}

    # -------------------------
    # 5. API Validation
    # -------------------------
    logger.info("Validating API specifications...")
    try:
        api_results = api_validator.validate_api_spec_and_flows(project_path)
    except Exception as e:
        logger.error(f"API validation failed: {e}")
        api_results = {}

    # -------------------------
    # 6. Logging Validation
    # -------------------------
    logger.info("Validating logging practices...")
    try:
        logging_results = logs_reviewer.validate_logging(project_path)
    except Exception as e:
        logger.error(f"Logging validation failed: {e}")
        logging_results = {}

    # -------------------------
    # 7. Orphan Checker
    # -------------------------
    logger.info("Starting orphan check analysis...")
    try:
        orphan_checker = MuleComprehensiveOrphanChecker(project_path)
        
        reports_dir = os.path.dirname(output_path)
        orphan_html_path = os.path.join(reports_dir, "orphan_report.html")
        orphan_md_path = os.path.join(reports_dir, "bitbucket_orphan_comment.md")
        
        orphan_report = orphan_checker.run(
            html_output_path=orphan_html_path,
            bitbucket_md_path=orphan_md_path
        )
        
        logger.info(f"Orphan check completed: {orphan_report['summary']['total_orphaned_items']} orphaned items found")
        
    except Exception as e:
        logger.error(f"Orphan check failed: {e}", exc_info=True)
        orphan_report = {
            "summary": {"total_orphaned_items": 0},
            "orphans": {},
            "used": {},
            "declared": {},
            "files_processed": {},
            "validation_errors": [str(e)]
        }

    # -------------------------
    # 8. Evaluate Thresholds
    # -------------------------
    threshold_warnings = []
    
    # Flow thresholds
    total_flows = flow_results.get("total_flows", 0)
    total_sub_flows = flow_results.get("total_sub_flows", 0)
    total_components = flow_results.get("total_components", 0)
    
    if total_flows > args.max_flows:
        threshold_warnings.append(f"{total_flows} flows exceed max allowed {args.max_flows}")
    if total_sub_flows > args.max_sub_flows:
        threshold_warnings.append(f"{total_sub_flows} sub-flows exceed max allowed {args.max_sub_flows}")
    if total_components > args.max_components:
        threshold_warnings.append(f"{total_components} components exceed max allowed {args.max_components}")
    
    # Build size threshold
    build_size_mb = dependency_results.get("build_size_mb", 0)
    if build_size_mb > args.max_build_size_mb:
        threshold_warnings.append(f"Build size {build_size_mb}MB exceeds max allowed {args.max_build_size_mb}MB")

    # -------------------------
    # 9. Prepare results dictionary
    # -------------------------
    end_time = datetime.now()
    duration = end_time - start_time
    git_branch = get_git_branch(project_path)

    all_results = {
        "project_name": os.path.basename(project_path),
        "git_branch_name": git_branch,
        "git_branch": git_branch,
        "report_start_time": start_time.strftime("%Y-%m-%d %H:%M:%S"),
        "report_end_time": end_time.strftime("%Y-%m-%d %H:%M:%S"),
        "report_duration": str(duration),
        "timestamp": end_time.strftime("%Y-%m-%d %H:%M:%S"),
        "python_version": f"{sys.version_info.major}.{sys.version_info.minor}.{sys.version_info.micro}",
        
        # Validation results
        "code_reviewer_issues": code_reviewer_results,
        "yaml_validation": yaml_results,
        "dependency_validation": dependency_results,
        "flow_validation": flow_results,
        "api_validation": api_results,
        "logging_validation": logging_results,
        "orphan_checker": orphan_report,
        "project_uses_secure_properties": project_uses_secure_properties,
        "threshold_warnings": threshold_warnings,
    }

    # Calculate status
    all_results["status"] = calculate_status(all_results)

    # Quality Metrics Scorecard
    orphan_flows = orphan_report.get("summary", {}).get("orphan_flows_count", 0)
    invalid_names = len(flow_results.get("invalid_flow_names", []))

    scorecard = [
        {"metric": "API Spec Found", "value": "Yes" if api_results.get("api_spec_zip_found") else "No", 
         "status": "PASS" if api_results.get("api_spec_zip_found") else "FAIL"},
        {"metric": "Total Flows", "value": total_flows, 
         "status": "PASS" if total_flows <= args.max_flows else "WARN"},
        {"metric": "Sub-Flows", "value": total_sub_flows, 
         "status": "PASS" if total_sub_flows <= args.max_sub_flows else "WARN"},
        {"metric": "Components", "value": total_components, 
         "status": "PASS" if total_components <= args.max_components else "WARN"},
        {"metric": "Orphan Flows", "value": orphan_flows, 
         "status": "PASS" if orphan_flows == 0 else "WARN"},
        {"metric": "Invalid Names", "value": invalid_names, 
         "status": "PASS" if invalid_names == 0 else "WARN"},
    ]
    all_results["scorecard"] = scorecard

    # -------------------------
    # 10. Generate main HTML report
    # -------------------------
    template_string = load_template(template_path)
    html_report = html_reporter.generate_html_report(all_results, template_string)

    # -------------------------
    # 11. Save main report
    # -------------------------
    save_report(output_path, html_report)

    # -------------------------
    # 12. Generate standalone orphan report page
    # -------------------------
    orphan_html = generate_orphan_report_page(
        orphan_report,
        project_name=all_results["project_name"]
    )

    orphan_report_path = os.path.join(
        os.path.dirname(output_path),
        "orphan_report.html"
    )

    save_report(orphan_report_path, orphan_html)

    logger.info("Mule Validator CLI execution completed successfully!")
    logger.info(f"Overall Status: {all_results['status']}")

# -------------------------
# Entry point
# -------------------------
if __name__ == "__main__":
    main()