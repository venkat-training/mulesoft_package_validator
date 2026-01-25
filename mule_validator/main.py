"""
Main entry point for the MuleSoft Package Validator CLI tool.
This script orchestrates the validation of a MuleSoft package by invoking various
validators for dependencies, flows, API specifications, YAML configurations,
MuleSoft code review, logging practices, and component structure.

It serves as the command-line interface (CLI) for the MuleSoft Package Validator.
The script handles argument parsing, invokes Maven for project build, calls
individual validator modules, aggregates results, and generates an HTML report.
"""
import argparse
import subprocess
import logging
import sys
import os
import datetime
import shutil
from .dependency_validator import validate_all_projects
from .flow_validator import validate_flows_in_package
from .code_reviewer import review_all_files
from .api_validator import validate_api_spec_and_flows
from .configfile_validator import validate_files
from .logs_reviewer import validate_logging
from .html_reporter import generate_html_report
from .mule_orphan_checker import MuleComprehensiveOrphanChecker

logger = logging.getLogger(__name__)


def get_maven_command():
    """
    Resolves the Maven executable correctly across platforms.
    On Windows, this resolves mvn.cmd or mvn.bat.
    """
    mvn_cmd = shutil.which("mvn")
    if mvn_cmd:
        return mvn_cmd
    return None

def get_current_git_branch(repo_path):
    """
    Returns the current git branch name for the Git repository at the given path.
    """
    try:
        result = subprocess.run(
            ["git", "rev-parse", "--abbrev-ref", "HEAD"],
            cwd=repo_path,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            check=False,
            timeout=5
        )
        if result.returncode == 0:
            return result.stdout.strip()
        else:
            logger.warning(f"Failed to get Git branch for {repo_path}. Error: {result.stderr.strip()}")
            return "Unknown"
    except FileNotFoundError:
        logger.error("Git command not found. Ensure Git is installed and in PATH.")
        return "Unknown"
    except subprocess.TimeoutExpired:
        logger.warning(f"Git command timed out for {repo_path}.")
        return "Unknown"
    except Exception as e:
        logger.error(f"An error occurred while getting Git branch for {repo_path}: {e}")
        return "Unknown"

def ensure_maven_and_build(project_dir: str) -> bool:
    """
    Ensures Maven is available and successfully runs `mvn clean install -DskipTests`.
    Returns True if successful, False otherwise.
    """
    try:
        # Check Maven version
        mvn_cmd = get_maven_command()

        if not mvn_cmd:
            print("ERROR: Maven command 'mvn' not found. Ensure Maven is installed and in PATH.")
            logger.error("Maven command 'mvn' not found during version check.")
            return False

        result_mvn_version = subprocess.run(
            [mvn_cmd, "-v"],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True
        )

        if result_mvn_version.returncode != 0:
            print("ERROR: Maven not found. Please install Maven and ensure it's in PATH.")
            logger.error(f"Maven version check failed. Output: {result_mvn_version.stdout} Error: {result_mvn_version.stderr}")
            return False
    except FileNotFoundError:
        print("ERROR: Maven command 'mvn' not found. Ensure Maven is installed and in PATH.")
        logger.error("Maven command 'mvn' not found during version check.")
        return False
    except Exception as e:
        print(f"ERROR: Unexpected error checking Maven: {e}")
        logger.error(f"Unexpected error during Maven version check: {e}")
        return False

    logger.info(f"Running 'mvn clean install -DskipTests' in directory: {project_dir}")
    try:
        build_process = subprocess.run(
            [mvn_cmd, "clean", "install", "-DskipTests"],
            cwd=project_dir,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True
        )
        if build_process.returncode != 0:
            print("\nERROR: Maven build failed. Validation cannot proceed.")
            print("Maven stdout:\n", build_process.stdout)
            print("Maven stderr:\n", build_process.stderr)
            logger.error(f"Maven build failed with return code {build_process.returncode}.")
            return False
        logger.info("Maven build successful.")
        return True
    except FileNotFoundError:
        print("ERROR: Maven command 'mvn' not found for build. Ensure Maven is installed and in PATH.")
        logger.error("Maven command 'mvn' not found during build execution.")
        return False
    except Exception as e:
        print(f"ERROR: Unexpected error during Maven build: {e}")
        logger.error(f"Unexpected error during Maven build: {e}")
        return False

def evaluate_thresholds(flow_results, dependency_results, thresholds):
    """
    Evaluates threshold violations and returns a dictionary of warnings.
    """
    warnings = {}

    # Flow thresholds
    total_flows = flow_results.get("total_flows", 0)
    total_sub_flows = flow_results.get("total_sub_flows", 0)
    total_components = flow_results.get("total_components", 0)

    if total_flows > thresholds.get("max_flows", 100):
        warnings["flows"] = f"{total_flows} flows exceed max allowed {thresholds.get('max_flows')}"
    if total_sub_flows > thresholds.get("max_sub_flows", 50):
        warnings["sub_flows"] = f"{total_sub_flows} sub-flows exceed max allowed {thresholds.get('max_sub_flows')}"
    if total_components > thresholds.get("max_components", 500):
        warnings["components"] = f"{total_components} components exceed max allowed {thresholds.get('max_components')}"

    # Build size threshold (in MB)
    build_size_mb = dependency_results.get("build_size_mb", 0)
    if build_size_mb > thresholds.get("max_build_size_mb", 100):
        warnings["build_size"] = f"Build size {build_size_mb}MB exceeds max allowed {thresholds.get('max_build_size_mb')}MB"

    return warnings

def calculate_status(all_results):
    if all_results.get("build_failed"):
        return "FAIL"

    orphan_count = all_results.get("orphan_checker", {}).get("summary", {}).get("orphan_flows_count", 0)
    if orphan_count > 0:
        return "WARN"

    if all_results.get("threshold_warnings"):
        return "WARN"

    return "PASS"


def main() -> None:
    """
    CLI entry point for MuleSoft validation.
    """
    start_time = datetime.datetime.now()
    logging.basicConfig(
        level=logging.INFO,
        format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
        handlers=[logging.StreamHandler(sys.stdout)]
    )
    logger = logging.getLogger(__name__)

    parser = argparse.ArgumentParser(
        description='Validate a MuleSoft package, checking API specs, flows, YAML configs, and more.'
    )
    parser.add_argument('package_folder_path', type=str, help='MuleSoft package folder path.')
    parser.add_argument('--report-file', type=str, help='Path to save the main HTML validation report.')
    parser.add_argument('--orphan-report-file', type=str, help='Path to save separate orphan HTML report.')
    parser.add_argument('--fail-on', choices=['WARN', 'ERROR'], help='Fail the validation with exit code based on status severity.')
    threshold_group = parser.add_argument_group('Validation Thresholds')
    threshold_group.add_argument('--max-build-size-mb', type=int, default=100)
    threshold_group.add_argument('--max-flows', type=int, default=100)
    threshold_group.add_argument('--max-sub-flows', type=int, default=50)
    threshold_group.add_argument('--max-components', type=int, default=500)

    args = parser.parse_args()
    package_folder_path = args.package_folder_path
    

    all_results = {}
    success = ensure_maven_and_build(package_folder_path)
    all_results["build_failed"] = not success
    if not success:
        sys.exit(1)

    logger.info(f"Starting validation for: {package_folder_path}")

    # Step 1: Code Review
    logger.info("Reviewing code and flows...")
    code_reviewer_results, project_uses_secure_properties = review_all_files(package_folder_path)

    # Step 2: YAML Validation
    logger.info("Validating YAML configurations...")
    yaml_results = validate_files(package_folder_path, project_uses_secure_properties)

    # Step 3: Dependency Validation
    logger.info("Validating dependencies and build size...")
    dependency_results = validate_all_projects(package_folder_path)

    # Step 4: Flows Validation
    logger.info("Validating flows and components...")
    flow_results = validate_flows_in_package(
        package_folder_path,
        max_flows=args.max_flows,
        max_sub_flows=args.max_sub_flows,
        max_components=args.max_components
    )

    # Step 5: API Validation
    logger.info("Validating API specifications...")
    api_results = validate_api_spec_and_flows(package_folder_path)

    # Step 6: Logging Validation
    logger.info("Validating logging practices...")
    logging_results = validate_logging(package_folder_path)

    # Step 7: Git branch
    git_branch = get_current_git_branch(package_folder_path)

    # Step 8: Orphan Checker
    logger.info("Running orphan flow analysis...")
    orphan_checker = MuleComprehensiveOrphanChecker(package_folder_path)
    orphan_results = orphan_checker.run()

    # Step 9: Threshold evaluation
    thresholds = {
        "max_flows": args.max_flows,
        "max_sub_flows": args.max_sub_flows,
        "max_components": args.max_components,
        "max_build_size_mb": args.max_build_size_mb
    }
    threshold_warnings = evaluate_thresholds(flow_results, dependency_results, thresholds)

    # Step 10: Aggregate results
    end_time = datetime.datetime.now()
    duration = end_time - start_time

    all_results.update({
        "yaml_validation": yaml_results,
        "dependency_validation": dependency_results,
        "flow_validation": flow_results,
        "api_validation": api_results,
        "code_reviewer_issues": code_reviewer_results,
        "project_uses_secure_properties": project_uses_secure_properties,
        "logging_validation": logging_results,
        "git_branch": git_branch,
        "orphan_checker": orphan_results,
        "thresholds": thresholds,
        "threshold_warnings": threshold_warnings,
        "report_start_time": start_time.strftime('%Y-%m-%d %H:%M:%S'),
        "report_end_time": end_time.strftime('%Y-%m-%d %H:%M:%S'),
        "report_duration": str(duration)
    })

    # Calculate status
    all_results["status"] = calculate_status(all_results)
    all_results["project_name"] = os.path.basename(package_folder_path)
    all_results["timestamp"] = all_results["report_end_time"]
    all_results["python_version"] = f"{sys.version_info.major}.{sys.version_info.minor}.{sys.version_info.micro}"

    # Quality Metrics Scorecard
    total_flows = flow_results.get("total_flows", 0)
    total_sub_flows = flow_results.get("total_sub_flows", 0)
    total_components = flow_results.get("total_components", 0)
    orphan_flows = orphan_results.get("summary", {}).get("orphan_flows_count", 0)
    invalid_names = len(flow_results.get("invalid_flow_names", []))

    scorecard = [
        {"metric": "Total Flows", "value": total_flows, "status": "PASS" if total_flows <= args.max_flows else "WARN"},
        {"metric": "Sub-Flows", "value": total_sub_flows, "status": "PASS" if total_sub_flows <= args.max_sub_flows else "WARN"},
        {"metric": "Components", "value": total_components, "status": "PASS" if total_components <= args.max_components else "WARN"},
        {"metric": "Orphan Flows", "value": orphan_flows, "status": "PASS" if orphan_flows == 0 else "WARN"},
        {"metric": "Invalid Names", "value": invalid_names, "status": "PASS" if invalid_names == 0 else "WARN"},
    ]
    all_results["scorecard"] = scorecard

    # Determine exit code based on fail-on option
    exit_code = 0
    if args.fail_on == "WARN" and all_results["status"] in ["WARN", "FAIL"]:
        exit_code = 1
    elif args.fail_on == "ERROR" and all_results["status"] == "FAIL":
        exit_code = 2

    # Console summary
    print("\n====== VALIDATION SUMMARY ======")
    print(f"Git branch: {git_branch}")
    if threshold_warnings:
        print("Threshold warnings:")
        for k, v in threshold_warnings.items():
            print(f"  - {v}")
    if 'summary' in orphan_results:
        print("\nOrphan Checker Summary:")
        for k, v in orphan_results['summary'].items():
            print(f"  {k}: {v}")
    print("===============================")

    # HTML Report
    if args.report_file:
        os.makedirs(os.path.dirname(args.report_file), exist_ok=True)
    if args.orphan_report_file:
        os.makedirs(os.path.dirname(args.orphan_report_file), exist_ok=True)
    try:
        current_dir = os.path.dirname(os.path.abspath(__file__))
        template_path = os.path.join(current_dir, "report_template.html")
        with open(template_path, "r", encoding="utf-8") as f_template:
            template_content = f_template.read()
            
        report_html = generate_html_report(all_results, template_content)
        with open(args.report_file, 'w') as f:
            f.write(report_html)
        print(f"\nHTML report generated at: {args.report_file}")

        # Orphan report separately if requested
        if args.orphan_report_file and hasattr(orphan_checker, "generate_html_report"):
            orphan_checker.generate_html_report(orphan_results, args.orphan_report_file)
            print(f"Orphan HTML report generated at: {args.orphan_report_file}")

    except FileNotFoundError:
        print("Error: HTML template not found. Report not generated.")
    except Exception as e:
        print(f"Error generating HTML report: {e}")

    # Exit with determined code
    sys.exit(exit_code)

def run(
    package_folder_path: str,
    mode: str = "full",
    report_file: str | None = None,
    orphan_report_file: str | None = None,
    max_flows: int = 100,
    max_sub_flows: int = 50,
    max_components: int = 500,
    fail_on: str | None = None,
):
    """
    Programmatic entry point for automation.
    Modes: full, list-flows, orphan-check
    """
    thresholds = {
        "max_flows": max_flows,
        "max_sub_flows": max_sub_flows,
        "max_components": max_components,
        "max_build_size_mb": 100  # default build size threshold
    }

    if mode == "list-flows":
        flow_results = validate_flows_in_package(
            package_folder_path,
            max_flows=max_flows,
            max_sub_flows=max_sub_flows,
            max_components=max_components
        )
        return flow_results

    if mode == "orphan-check":
        orphan_checker = MuleComprehensiveOrphanChecker(package_folder_path)
        return orphan_checker.run()

    # Full validation
    success = ensure_maven_and_build(package_folder_path)
    results = {"build_failed": not success}
    if not success:
        sys.exit(1)

    code_results, project_uses_secure_properties = review_all_files(package_folder_path)
    yaml_results = validate_files(package_folder_path, project_uses_secure_properties)
    dependency_results = validate_all_projects(package_folder_path)
    flow_results = validate_flows_in_package(package_folder_path, max_flows, max_sub_flows, max_components)
    api_results = validate_api_spec_and_flows(package_folder_path)
    logging_results = validate_logging(package_folder_path)
    git_branch = get_current_git_branch(package_folder_path)
    orphan_checker = MuleComprehensiveOrphanChecker(package_folder_path)
    orphan_results = orphan_checker.run()
    threshold_warnings = evaluate_thresholds(flow_results, dependency_results, thresholds)

    results.update({
        "yaml_validation": yaml_results,
        "dependency_validation": dependency_results,
        "flow_validation": flow_results,
        "api_validation": api_results,
        "code_reviewer_issues": code_results,
        "project_uses_secure_properties": project_uses_secure_properties,
        "logging_validation": logging_results,
        "git_branch": git_branch,
        "orphan_checker": orphan_results,
        "thresholds": thresholds,
        "threshold_warnings": threshold_warnings
    })

    # Calculate status and fail fast
    results["status"] = calculate_status(results)
    results["project_name"] = os.path.basename(package_folder_path)
    results["timestamp"] = datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')
    results["python_version"] = f"{sys.version_info.major}.{sys.version_info.minor}.{sys.version_info.micro}"

    # Determine exit code
    exit_code = 0
    if fail_on == "WARN" and results["status"] in ["WARN", "FAIL"]:
        exit_code = 1
    elif fail_on == "ERROR" and results["status"] == "FAIL":
        exit_code = 2

    if report_file:
        current_dir = os.path.dirname(os.path.abspath(__file__))
        template_path = os.path.join(current_dir, "report_template.html")

        with open(template_path, "r", encoding="utf-8") as f:
            template_content = f.read()
            report_html = generate_html_report(results, template_content)
        with open(report_file, 'w') as f:
            f.write(report_html)

    if orphan_report_file:
        if hasattr(orphan_checker, "generate_html_report"):
            orphan_checker.generate_html_report(orphan_results, orphan_report_file)

    if exit_code != 0:
        sys.exit(exit_code)

    return results


if __name__ == "__main__":
    main()
