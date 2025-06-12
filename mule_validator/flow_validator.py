import os
import xml.etree.ElementTree as ET
import logging
import re

# Configure logging
logger = logging.getLogger(__name__)

"""
Validates MuleSoft flow definitions within XML configuration files.

This module focuses on:
- Validating flow and sub-flow names against specific naming conventions.
  This includes checking for camel case, handling of HTTP verb prefixes
  (e.g., "get:", "post:"), APIkit-style suffixes (e.g., ":config"),
  quoted names, and ignoring certain common substrings or patterns.
- Counting the total number of flows, sub-flows, and components within
  Mule XML files in a package.
- Comparing these counts against configurable maximum thresholds.
- Reporting any flow names that do not adhere to the defined naming standards.
"""

# Define constants
MULE_CORE_NAMESPACE_URI = "http://www.mulesoft.org/schema/mule/core"

# Define ignored substrings for flow names
IGNORED_FLOW_NAME_SUBSTRINGS = ["-main", "-console"]

# Define common HTTP verbs to ignore as prefixes in flow names (e.g., "get:", "post:").
HTTP_VERBS = ["get", "post", "put", "delete", "patch", "head", "options", "trace"]

# Define common mime types to handle
COMMON_MIME_TYPES = [
    "text/csv", "text/plain", "text/xml", "text/html",
    "application/json", "application/xml", "application/octet-stream",
    "image/jpeg", "image/png"
]

def is_camel_case(s):
    """
    Checks if a string is in a simplified camel case format.

    The rules are:
    - A leading backslash ('\') is removed before validation.
    - An empty string after backslash removal is considered valid (as it might be a placeholder).
    - Strings containing underscores (`_`) or hyphens (`-`) are invalid.
    - All-uppercase strings with more than one character (e.g., "FLOW") are invalid.
      A single uppercase character (e.g., "F") is considered valid (common for acronyms).
    - Otherwise, the string should generally start with a lowercase letter if it's multi-character.
      However, this function primarily checks for invalid characters and all-caps.
      A more strict initial lowercase check is implicitly handled by typical camel case usage.

    Args:
        s (str): The string to check.

    Returns:
        bool: True if the string conforms to the defined camel case rules, False otherwise.
    """
    # Handle leading backslashes: if the string starts with '\', remove it.
    if s and s.startswith('\\'):
        s = s[1:]

    if not s: # Empty string is considered valid (e.g. after processing or if it's a placeholder)
        return True
    if "_" in s or "-" in s: # Underscores or hyphens are not allowed
        return False
    # All-uppercase strings (e.g., "FLOW") are not camel case, unless it's a single letter (e.g., "F")
    if s.isupper() and len(s) > 1:
        return False
    # Standard camel case usually starts with a lowercase letter, but this function
    # focuses more on what's *not* allowed (underscores, hyphens, all-caps).
    # The first letter check (s[0].islower()) can be too strict if single-letter uppercase
    # or acronyms like "processHTTPRequest" are desired.
    # The primary check here is for common violations.
    return True # If no invalid patterns are found, assume it's acceptable.

def validate_flow_name_camel_case(flow_name: str) -> bool:
    """
    Validates if the core part of a Mule flow name follows specific camel case rules,
    after processing prefixes, suffixes, and quotes.

    The function processes the `flow_name` to extract the main part to be validated:
    1. HTTP Verb Prefix Handling: If the name starts with a recognized HTTP verb
       followed by a colon (e.g., "get:actualFlowName", "post:createOrder:config"),
       the verb and colon are stripped.
    2. Suffix Handling: If the name contains colons, the part after the first relevant
       colon (if not part of a verb prefix) or second colon (if a verb prefix was present)
       is considered a suffix and is stripped.
       For example:
       - "actualFlowName:some-config" -> "actualFlowName" is validated.
       - "get:actualFlowName:some-config" -> "actualFlowName" is validated.
       - "actualFlowName:config1:config2" -> "actualFlowName" is validated.
    3. Quoted Names: If the extracted name part is enclosed in single or double quotes,
       these quotes are removed.

    The extracted and processed `name_to_validate` is then checked:
    - If it matches any entry in `COMMON_MIME_TYPES`, it's considered valid.
    - Otherwise, its camel case status is determined by `is_camel_case()`.

    Args:
        flow_name (str): The flow name to validate.

    Returns:
        bool: True if the flow name is considered valid according to the rules, False otherwise.
    """
    # Ignore if the original flow name contains -main or -console
    if any(sub in flow_name for sub in IGNORED_FLOW_NAME_SUBSTRINGS):
        logger.debug(f"Ignoring flow name due to substring: {flow_name}")
        return True

    name_to_validate = flow_name
    parts = flow_name.split(':')

    if len(parts) == 1:
        name_to_validate = parts[0]
    elif len(parts) == 2:
        if parts[0].lower() in HTTP_VERBS:
            name_to_validate = parts[1]
        else:
            name_to_validate = parts[0]
    elif len(parts) > 2:
        if parts[0].lower() in HTTP_VERBS:
            name_to_validate = parts[1]
        else:
            name_to_validate = parts[0]

    # Remove quotes if the extracted name_to_validate is enclosed in them.
    if name_to_validate.startswith('"') and name_to_validate.endswith('"') and len(name_to_validate) > 1:
        name_to_validate = name_to_validate[1:-1]
    elif name_to_validate.startswith("'") and name_to_validate.endswith("'") and len(name_to_validate) > 1:
        name_to_validate = name_to_validate[1:-1]

    # Ignore if the validated part contains a backslash anywhere
    if "\\" in name_to_validate:
        logger.debug(f"Ignoring flow name due to backslash: {name_to_validate}")
        return True

    if name_to_validate in COMMON_MIME_TYPES:
        return True

    return is_camel_case(name_to_validate)

def count_flows_and_components(xml_file_path):
    """
    Parses a Mule XML file to count the number of flows, sub-flows, and components,
    and validates flow names for camel case.
    Args:
        xml_file_path (str): Path to the Mule XML configuration file.

    Returns:
        tuple[dict[str, int], list[str]]: A tuple containing:
            - A dictionary with counts for 'flows', 'sub_flows', and 'components' found in the file.
            - A list of flow/sub-flow names from this file that were found to be invalid
              according to `validate_flow_name_camel_case`. Sub-flow names in the list
              are prefixed with "subflow:".
    """
    counts = {'flows': 0, 'sub_flows': 0, 'components': 0}
    invalid_flow_names = [] # To store names that fail camel case validation
    logger.debug(f"Attempting to parse XML file: {xml_file_path}")
    try:
        tree = ET.parse(xml_file_path)
        root = tree.getroot()

        # Count flows and validate their names
        for flow_element in root.findall(f'.//{{{MULE_CORE_NAMESPACE_URI}}}flow'):
            counts['flows'] += 1
            counts['components'] += len(flow_element)  # Count components within flows
            flow_name = flow_element.get('name')
            if flow_name:
                if not validate_flow_name_camel_case(flow_name):
                    invalid_flow_names.append(flow_name)

        # Count sub-flows (and validate their names if needed)
        for sub_flow_element in root.findall(f'.//{{{MULE_CORE_NAMESPACE_URI}}}sub-flow'):
            counts['sub_flows'] += 1
            counts['components'] += len(sub_flow_element)  # Count components within sub-flows
            sub_flow_name = sub_flow_element.get('name')
            if sub_flow_name:
                if not validate_flow_name_camel_case(sub_flow_name):
                    invalid_flow_names.append(f"subflow:{sub_flow_name}")

        logger.debug(f"Successfully parsed {xml_file_path}: {counts}, Invalid names: {invalid_flow_names}")

    except ET.ParseError as e:
        logger.error(f"Error parsing XML file: {xml_file_path} - {e}")
        return counts, []
    except FileNotFoundError:
        logger.error(f"XML file not found: {xml_file_path}")
        return counts, []
    
    return counts, invalid_flow_names

def validate_flows_in_package(package_folder_path, max_flows=100, max_sub_flows=50, max_components=500):
    """
    Validates the number of flows, sub-flows, and components in a MuleSoft package.
    Validates flows within all Mule XML configuration files in a MuleSoft package
    located under `src/main/mule/`.

    It aggregates counts of flows, sub-flows, and components from all XML files
    and checks them against specified maximum limits. It also collects all flow
    names that violate naming conventions.

    Args:
        package_folder_path (str): The path to the root of the MuleSoft package folder.
        max_flows (int, optional): Maximum allowed total number of flows in the package.
                                   Defaults to 100.
        max_sub_flows (int, optional): Maximum allowed total number of sub-flows.
                                       Defaults to 50.
        max_components (int, optional): Maximum allowed total number of components
                                        (elements within flows and sub-flows). Defaults to 500.

    Returns:
        dict: A dictionary containing the validation results:
            - 'total_counts' (dict[str, int]): Contains total 'flows', 'sub_flows',
              and 'components' found.
            - 'flows_ok' (bool): True if total flows are within `max_flows`.
            - 'sub_flows_ok' (bool): True if total sub-flows are within `max_sub_flows`.
            - 'components_ok' (bool): True if total components are within `max_components`.
            - 'flow_names_camel_case_ok' (bool): True if no invalid flow names were found.
            - 'invalid_flow_names' (list[str]): A list of all flow/sub-flow names
              that failed validation.
            - 'max_flows_limit' (int): The `max_flows` value used for validation.
            - 'max_sub_flows_limit' (int): The `max_sub_flows` value used.
            - 'max_components_limit' (int): The `max_components` value used.

    Raises:
        FileNotFoundError: If the `src/main/mule` directory does not exist.
    """
    src_main_mule_path = os.path.join(package_folder_path, 'src', 'main', 'mule')
    logger.info(f"Validating flows in package: {package_folder_path}")
    logger.info(f"Using thresholds - Max Flows: {max_flows}, Max Sub-Flows: {max_sub_flows}, Max Components: {max_components}")

    if not os.path.isdir(src_main_mule_path):
        logger.error(f"Mule source directory does not exist: {src_main_mule_path}")
        raise FileNotFoundError(f"Mule source directory does not exist: {src_main_mule_path}")

    total_counts = {'flows': 0, 'sub_flows': 0, 'components': 0}
    all_invalid_flow_names = []
    logger.info(f"Scanning directory {src_main_mule_path} for Mule XML files.")
    
    xml_files_found = False
    for root_dir, _, files in os.walk(src_main_mule_path):
        for file in files:
            if file.endswith('.xml'):
                xml_files_found = True
                file_path = os.path.join(root_dir, file)
                logger.debug(f"Processing file: {file_path}")
                file_counts, invalid_names_in_file = count_flows_and_components(file_path)
                total_counts['flows'] += file_counts['flows']
                total_counts['sub_flows'] += file_counts['sub_flows']
                total_counts['components'] += file_counts['components']
                if invalid_names_in_file:
                    all_invalid_flow_names.extend(invalid_names_in_file)
    
    if not xml_files_found:
        logger.warning(f"No XML files found in {src_main_mule_path}. Counts will be zero.")

    flows_ok = total_counts['flows'] <= max_flows
    sub_flows_ok = total_counts['sub_flows'] <= max_sub_flows
    components_ok = total_counts['components'] <= max_components
    flow_names_camel_case_ok = not all_invalid_flow_names

    if not flows_ok:
        logger.warning(f"Flow count {total_counts['flows']} exceeds limit of {max_flows}.")
    if not sub_flows_ok:
        logger.warning(f"Sub-flow count {total_counts['sub_flows']} exceeds limit of {max_sub_flows}.")
    if not components_ok:
        logger.warning(f"Component count {total_counts['components']} exceeds limit of {max_components}.")
    if not flow_names_camel_case_ok:
        logger.warning(f"Found invalid flow names (non-camelCase or other issues): {all_invalid_flow_names}")

    return {
        'total_counts': total_counts,
        'flows_ok': flows_ok,
        'sub_flows_ok': sub_flows_ok,
        'components_ok': components_ok,
        'flow_names_camel_case_ok': flow_names_camel_case_ok,
        'invalid_flow_names': all_invalid_flow_names,
        'max_flows_limit': max_flows,
        'max_sub_flows_limit': max_sub_flows,
        'max_components_limit': max_components
    }