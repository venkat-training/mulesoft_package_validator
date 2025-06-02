import os
from lxml import etree
import logging

NAMESPACE = {"mule": "http://www.mulesoft.org/schema/mule/core"}
logger = logging.getLogger(__name__)

def find_logger_issues_in_project(project_path):
    """
    Scans all Mule XML files in src/main/mule for logger issues.
    Returns a list of dicts with logger findings.
    """
    mule_config_path = os.path.join(project_path, "src/main/mule")
    all_issues = []
    for root, _, files in os.walk(mule_config_path):
        for f in files:
            if f.endswith(".xml"):
                file_path = os.path.join(root, f)
                all_issues.extend(find_logger_issues(file_path))
    return all_issues

def find_logger_issues(file_path):
    """
    Finds logger issues in a single Mule XML file.
    Returns a list of dicts.
    """
    issues = []
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
    Analyzes log4j2.xml for risky root logger levels.
    Returns a list of warning strings.
    """
    log4j_path = os.path.join(project_path, "src/main/resources/log4j2.xml")
    warnings = []
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
    Main entry point for the package validator framework.
    Returns a dict with logger issues and log4j warnings.
    """
    return {
        "logger_issues": find_logger_issues_in_project(project_path),
        "log4j_warnings": analyze_log4j_config(project_path)
    }