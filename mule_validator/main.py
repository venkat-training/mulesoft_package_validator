"""
Main entry point for the MuleSoft Package Validator CLI tool.

This script orchestrates the validation of a MuleSoft package by invoking various
validators for dependencies, flows, API specifications, YAML configurations,
MuleSoft code review, logging practices, and component structure.

It serves as both:
- A CLI entry point
- A programmatic entry point (used by GitHub Copilot CLI)
"""

import argparse
import subprocess
import logging
import sys
import datetime

from .dependency_validator import validate_all_projects
from .flow_validator import validate_flows_in_package
from .code_reviewer import review_all_files
from .api_validator import validate_api_spec_and_flows
from .configfile_validator import validate_files
from .logs_reviewer import validate_logging
from .html_reporter import generate_html_report
from .mule_orphan_checker import MuleComprehensiveOrphanChecker

logger = logging.getLogger(__name__)


# ---------------------------------------------------------------------
# Utility functions
# ---------------------------------------------------------------------

def get_current_git_branch(repo_path: str) -> str:
    """Return current git branch name or 'Unknown'."""
    try:
        result = subprocess.run(
            ["git", "rev-parse", "--abbrev-ref", "HEAD"],
            cwd=repo_path,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            timeout=5
        )
        return result.stdout.strip() if result.returncode == 0 else "Unknown"
    except Exception:
        return "Unknown"


def ensure_maven_and_build(project_dir: str) -> None:
    """Ensure Maven exists and run mvn clean install -DskipTests."""
    try:
        subprocess.run(
            ["mvn", "-v"],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            check=True
        )
    except Exception:
        print("ERROR: Maven is not available. Please install Maven and ensure it is in PATH.")
        sys.exit(1)

    logger.info("Running Maven build (mvn clean install -DskipTests)")
    result = subprocess.run(
        ["mvn", "clean", "install", "-DskipTests"],
        cwd=project_dir,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True
    )

    if result.returncode != 0:
        print("\nERROR: Maven build failed.")
        print(result.stderr)
        sys.exit(1)

    logger.info("Maven build completed successfully")


# ---------------------------------------------------------------------
# CLI ENTRY POINT
# ---------------------------------------------------------------------

def main() -> None:
    start_time = datetime.datetime.now()

    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s - %(levelname)s - %(message)s",
        handlers=[logging.StreamHandler(sys.stdout)]
    )

    parser = argparse.ArgumentParser(
        description="Validate a MuleSoft package and perform architectural/code quality checks"
    )

    parser.add_argument("package_folder_path", help="Path to MuleSoft project")
    parser.add_argument("--report-file", help="Optional HTML report output path")
    parser.add_argument("--build-folder-path", default=None)

    thresholds = parser.add_argument_group("Validation Thresholds")
    thresholds.add_argument("--max-flows", type=int, default=100)
    thresholds.add_argument("--max-sub-flows", type=int, default=50)
    thresholds.add_argument("--max-components", type=int, default=500)

    args = parser.parse_args()
    project_path = args.package_folder_path

    logger.info(f"Starting MuleSoft validation for: {project_path}")

    ensure_maven_and_build(project_path)

    # Step 1: Code review
    code_review_results, uses_secure_props = review_all_files(project_path)

    # Step 2: Config/YAML validation
    yaml_results = validate_files(project_path, uses_secure_props)

    # Step 3: Dependency validation
    dependency_results = validate_all_projects(project_path)

    # Step 4: Flow validation
    flow_results = validate_flows_in_package(
        project_path,
        max_flows=args.max_flows,
        max_sub_flows=args.max_sub_flows,
        max_components=args.max_components
    )

    # Step 5: API validation
    api_results = validate_api_spec_and_flows(project_path)

    # Step 6: Logging validation
    logging_results = validate_logging(project_path)

    # Step 7: Git metadata
    git_branch = get_current_git_branch(project_path)

    # Step 8: Orphan flows
    orphan_checker = MuleComprehensiveOrphanChecker(project_path)
    orphan_report = orphan_checker.run()

    end_time = datetime.datetime.now()

    results = {
        "code_review": code_review_results,
        "yaml_validation": yaml_results,
        "dependency_validation": dependency_results,
        "flow_validation": flow_results,
        "api_validation": api_results,
        "logging_validation": logging_results,
        "orphan_checker": orphan_report,
        "uses_secure_properties": uses_secure_props,
        "git_branch": git_branch,
        "duration": str(end_time - start_time),
    }

    print("\nValidation completed successfully")
    if "summary" in orphan_report:
        print("Orphan flow summary:", orphan_report["summary"])

    if args.report_file:
        with open("mule_validator/report_template.html") as f:
            template = f.read()

        html = generate_html_report(results, template)
        with open(args.report_file, "w") as f:
            f.write(html)

        print(f"HTML report generated: {args.report_file}")

    logger.info("Validation finished")


# ---------------------------------------------------------------------
# PROGRAMMATIC ENTRY (Copilot CLI)
# ---------------------------------------------------------------------

def run(
    package_folder_path: str,
    mode: str = "full",
    report_file: str | None = None,
    max_flows: int = 100,
    max_sub_flows: int = 50,
    max_components: int = 500,
):
    logger.info(f"Running validator in '{mode}' mode")

    if mode == "list-flows":
        return validate_flows_in_package(
            package_folder_path,
            max_flows=max_flows,
            max_sub_flows=max_sub_flows,
            max_components=max_components
        )

    if mode == "orphan-check":
        checker = MuleComprehensiveOrphanChecker(package_folder_path)
        return checker.run()

    # FULL MODE
    ensure_maven_and_build(package_folder_path)

    code_results, secure_props = review_all_files(package_folder_path)
    yaml_results = validate_files(package_folder_path, secure_props)
    dependency_results = validate_all_projects(package_folder_path)
    flow_results = validate_flows_in_package(
        package_folder_path,
        max_flows=max_flows,
        max_sub_flows=max_sub_flows,
        max_components=max_components
    )
    api_results = validate_api_spec_and_flows(package_folder_path)
    logging_results = validate_logging(package_folder_path)

    checker = MuleComprehensiveOrphanChecker(package_folder_path)
    orphan_results = checker.run()

    results = {
        "code_review": code_results,
        "yaml_validation": yaml_results,
        "dependency_validation": dependency_results,
        "flow_validation": flow_results,
        "api_validation": api_results,
        "logging_validation": logging_results,
        "orphan_checker": orphan_results,
    }

    if report_file:
        with open("mule_validator/report_template.html") as f:
            template = f.read()
        with open(report_file, "w") as f:
            f.write(generate_html_report(results, template))

    return results


if __name__ == "__main__":
    main()
