import os
from lxml import etree
import logging
from typing import List, Dict, Any

"""
Reviews logging configurations in MuleSoft projects.

This module validates logging practices by:
- Scanning Mule XML configuration files (`src/main/mule/*.xml`) for:
    - Excessive use of `<logger>` components within a single flow.
    - Usage of "DEBUG" level loggers.
    - Usage of "ERROR" level loggers outside of recognized error handling scopes
      (basic check based on parent tag name).
- Analyzing the `log4j2.xml` file (`src/main/resources/log4j2.xml`) for:
    - Root logger configurations that are set to potentially overly verbose levels
      (DEBUG, TRACE, INFO), which might be unsuitable for production.
"""

NAMESPACE: Dict[str, str] = {"mule": "http://www.mulesoft.org/schema/mule/core"}
logger = logging.getLogger(__name__)

def find_logger_issues_in_project(project_path: str) -> List[Dict[str, Any]]:
    """
    Scans all Mule XML configuration files in the `src/main/mule` directory
    of a project for logger-related issues.

    It iterates through each XML file and calls `find_logger_issues` to
    aggregate findings.

    Args:
        project_path (str): The root path of the MuleSoft project.

    Returns:
        List[Dict[str, Any]]: A list of dictionaries, where each dictionary
        represents a logger issue found. The structure of these dictionaries
        is defined by `find_logger_issues`.
    """
    mule_config_path = os.path.join(project_path, "src/main/mule")
    all_issues: List[Dict[str, Any]] = []
    for root, _, files in os.walk(mule_config_path):
        for f in files:
            if f.endswith(".xml"):
                file_path = os.path.join(root, f)
                all_issues.extend(find_logger_issues(file_path))
    return all_issues

def find_logger_issues(file_path: str) -> List[Dict[str, Any]]:
    """
    Finds logger-related issues within a single Mule XML configuration file.

    Specifically, it checks each flow and sub-flow for:
    - More than 4 logger components.
    - Presence of loggers with level "DEBUG".
    - Presence of loggers with level "ERROR" that are not within an element
      whose tag name contains "errorHandler" (this is a heuristic and may not
      cover all valid error handling scenarios).

    Args:
        file_path (str): The path to the Mule XML file.

    Returns:
        List[Dict[str, Any]]: A list of dictionaries, where each dictionary
        represents a flow/sub-flow with identified logger issues.
        Each dictionary contains:
            - "file" (str): The base name of the XML file.
            - "flow" (str): The name of the flow or sub-flow.
            - "logger_count" (int): Total number of loggers in the flow.
            - "debug_count" (int): Number of DEBUG level loggers.
            - "error_count" (int): Number of ERROR level loggers.
            - "has_too_many_loggers" (bool): True if logger_count > 4.
            - "has_debug" (bool): True if debug_count > 0.
            - "error_outside_exception" (bool): True if error_count > 0 and
              the flow element's tag does not suggest it's an error handler.
    """
    issues: List[Dict[str, Any]] = []
    try:
        tree = etree.parse(file_path)
        root = tree.getroot()
        for flow_tag in ["flow", "sub-flow"]:
            for flow in root.findall(f".//mule:{flow_tag}", NAMESPACE):
                flow_name = flow.get("name")
                loggers = flow.findall(".//mule:logger", NAMESPACE)
                log_levels = [logger.get("level", "INFO").upper() for logger in loggers]
                debug_logs = [lvl for lvl in log_levels if lvl == "DEBUG"]
                error_logs = [lvl for lvl in log_levels if lvl == "ERROR"]

                issue = {
                    "file": os.path.basename(file_path),
                    "flow": flow_name,
                    "logger_count": len(loggers),
                    "debug_count": len(debug_logs),
                    "error_count": len(error_logs),
                    "has_too_many_loggers": len(loggers) > 4,
                    "has_debug": len(debug_logs) > 0,
                    "error_outside_exception": len(error_logs) > 0 and "errorHandler" not in flow.tag
                }
                if issue["has_too_many_loggers"] or issue["has_debug"] or issue["error_outside_exception"]:
                    issues.append(issue)
    except Exception as e:
        logger.error(f"Failed to parse {file_path}: {e}")
    return issues

def analyze_log4j_config(project_path):
    """
    Analyzes the `log4j2.xml` file for potentially risky root logger level configurations.

    It checks if the root logger level is set to "DEBUG", "TRACE", or "INFO",
    which might be too verbose for production environments.

    Args:
        project_path (str): The root path of the MuleSoft project.
                             The `log4j2.xml` is expected at `src/main/resources/log4j2.xml`.

    Returns:
        List[str]: A list of warning strings. Each string describes a detected issue.
                   Returns an empty list if no issues are found or if the file
                   cannot be parsed.
    """
    log4j_path = os.path.join(project_path, "src/main/resources/log4j2.xml")
    warnings: List[str] = []
    if not os.path.isfile(log4j_path):
        warnings.append(f"Log4j configuration file not found: {log4j_path}")
        return warnings
    try:
        tree = etree.parse(log4j_path)
        root_logger = tree.find(".//Root")
        if root_logger is not None:
            level = root_logger.get("level") or root_logger.get("Level")
            if level and level.upper() in ["DEBUG", "TRACE", "INFO"]:
                warnings.append(f"Root logger set to verbose level: {level}")
    except Exception as e:
        warnings.append(f"Error reading log4j2.xml: {e}")
    return warnings

def validate_logging(project_path):
    """
    Orchestrates all logging validation tasks for a MuleSoft project.

    This function serves as the main entry point for logging-related validations.
    It combines findings from Mule flow logger analysis and `log4j2.xml` configuration analysis.

    Args:
        project_path (str): The root path of the MuleSoft project.

    Returns:
        Dict[str, Any]: A dictionary containing the validation results:
            - "logger_issues" (List[Dict[str, Any]]): A list of issues found in
              Mule flow loggers, as returned by `find_logger_issues_in_project`.
            - "log4j_warnings" (List[str]): A list of warnings from the
              `log4j2.xml` analysis, as returned by `analyze_log4j_config`.
    """
    return {
        "logger_issues": find_logger_issues_in_project(project_path),
        "log4j_warnings": analyze_log4j_config(project_path)
    }