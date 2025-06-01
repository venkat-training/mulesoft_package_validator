import os
import xml.etree.ElementTree as ET
import logging

import re # For a potentially more robust camel case check later if needed

# Configure logging
logger = logging.getLogger(__name__)

# Define constants
MULE_CORE_NAMESPACE_URI = "http://www.mulesoft.org/schema/mule/core"

def count_flows_and_components(xml_file_path):
    """
    Parses a Mule XML file to count the number of flows, sub-flows, and components,
    and validates flow names for camel case.
    Args:
        xml_file_path (str): Path to the XML file.
    Returns:
        dict: A dictionary containing counts for flows, sub-flows, and components.
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
            # else: Flow has no name attribute. Decide if this is an issue. For now, only validating existing names.

        # Count sub-flows (and validate their names if needed)
        for sub_flow_element in root.findall(f'.//{{{MULE_CORE_NAMESPACE_URI}}}sub-flow'):
            counts['sub_flows'] += 1
            counts['components'] += len(sub_flow_element)  # Count components within sub-flows
            # Assuming camel case validation applies to sub-flow names as well.
            sub_flow_name = sub_flow_element.get('name')
            if sub_flow_name:
                if not validate_flow_name_camel_case(sub_flow_name):
                    # Potentially add to a different list or distinguish them if necessary
                    invalid_flow_names.append(f"subflow:{sub_flow_name}")
            # else: Sub-flow has no name.

        logger.debug(f"Successfully parsed {xml_file_path}: {counts}, Invalid names: {invalid_flow_names}")

    except ET.ParseError as e:
        logger.error(f"Error parsing XML file: {xml_file_path} - {e}")
        # Return empty list for invalid names in case of parse error
        return counts, []
    except FileNotFoundError: # ET.parse can also raise this
        logger.error(f"XML file not found: {xml_file_path}")
        # Return empty list for invalid names if file not found
        return counts, []
    
    return counts, invalid_flow_names

# Define ignored flow names
IGNORED_FLOW_NAMES = [
    "abc-xyz-integrationservices-main",
    "abc-xyz-integrationservices-console",
]

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
    Checks if a string is in camel case.
    A leading backslash ('\') is removed before validation.
    """
    # Handle leading backslashes: if the string starts with '\', remove it.
    if s and s.startswith('\\'):
        s = s[1:]

    if not s:
        return True
    if "_" in s or "-" in s:
        return False
    if s.isupper() and len(s) > 1: # "FLOW" is not camelCase, "F" is ok.
        return False
    # "flow" is ok. "flowName" is ok. "FlowName" is ok (PascalCase).
    # "flowname" (all lower but multiple words) would pass here if not caught by other project specific rules.
    # This basic check assumes that if not all lower, it should generally have some upper char mix
    # or be a single recognized word.
    # It does not strictly enforce starting with lowercase for camelCase vs PascalCase.
    return True


def validate_flow_name_camel_case(flow_name):
    """
    Validates if the core part of a flow name follows specific camel case rules.

    The function first checks if the `flow_name` is in a list of globally ignored names.
    If not, it processes the `flow_name` to extract the main part to be validated:
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
    if flow_name in IGNORED_FLOW_NAMES:
        return True # Globally ignored names take precedence

    name_to_validate = flow_name
    parts = flow_name.split(':')

    # Extract the core part of the flow name, stripping known prefixes and suffixes.
    if len(parts) == 1:
        # No colons, the whole name is the part to validate.
        name_to_validate = parts[0]
    elif len(parts) == 2:
        # Handles "verb:actualName" or "actualName:suffix".
        if parts[0].lower() in HTTP_VERBS:
            name_to_validate = parts[1]  # e.g., "get:actualName" -> "actualName"
        else:
            name_to_validate = parts[0]  # e.g., "actualName:some-config" -> "actualName"
    elif len(parts) > 2:
        # Handles "verb:actualName:suffix" or "actualName:suffix1:suffix2".
        # Primary target: "verb:actualName:some-config".
        if parts[0].lower() in HTTP_VERBS:
            name_to_validate = parts[1] # e.g., "get:actualFlowName:some-config" -> "actualFlowName"
        else:
            # If not starting with a verb, and has multiple colons,
            # assume the first part is the intended name, and the rest are suffixes.
            # e.g. "actualFlowName:config1:config2" -> "actualFlowName"
            name_to_validate = parts[0]
    # else: flow_name was empty or malformed in a way that split gives 0 parts,
    # in which case original flow_name (likely empty) is validated.

    # Remove quotes if the extracted name_to_validate is enclosed in them.
    # Example: flow_name = '"actualFlowName":config' -> name_to_validate becomes '"actualFlowName"' -> then "actualFlowName"


    # Rule: "text between the final """ - this implies quotes in the name.
    # Let's assume it means if the name_to_validate (after colon split and prefix/suffix stripping) is quoted, unquote it.
    # Example: flow_name = '"actualFlowName":config'
    # name_to_validate becomes '"actualFlowName"'
    if name_to_validate.startswith('"') and name_to_validate.endswith('"') and len(name_to_validate) > 1:
        name_to_validate = name_to_validate[1:-1]
    elif name_to_validate.startswith("'") and name_to_validate.endswith("'") and len(name_to_validate) > 1:
        name_to_validate = name_to_validate[1:-1]

    # Rule: Handle exceptions for flow names with embedded mime types.
    # Interpretation: if the `name_to_validate` itself is a known mime type, it's allowed.
    if name_to_validate in COMMON_MIME_TYPES:
        return True

    # The part "text between the final /" from my previous reasoning seems like overthinking based on the prompt.
    # The prompt was "text between the final "" and before the ":"".
    # The final "" part is handled by the unquoting logic above if the name itself contains quotes.

    return is_camel_case(name_to_validate)


def validate_flows_in_package(package_folder_path, max_flows=100, max_sub_flows=50, max_components=500):
    """
    Validates the number of flows, sub-flows, and components in a MuleSoft package.
    Args:
        package_folder_path (str): The path to the MuleSoft package folder.
        max_flows (int): Maximum allowed number of flows.
        max_sub_flows (int): Maximum allowed number of sub-flows.
        max_components (int): Maximum allowed number of components.
    Returns:
        dict: Validation results including counts and status flags for limits.
    """
    src_main_mule_path = os.path.join(package_folder_path, 'src', 'main', 'mule')
    logger.info(f"Validating flows in package: {package_folder_path}")
    logger.info(f"Using thresholds - Max Flows: {max_flows}, Max Sub-Flows: {max_sub_flows}, Max Components: {max_components}")


    if not os.path.isdir(src_main_mule_path):
        logger.error(f"Mule source directory does not exist: {src_main_mule_path}")
        raise FileNotFoundError(f"Mule source directory does not exist: {src_main_mule_path}")

    total_counts = {'flows': 0, 'sub_flows': 0, 'components': 0}
    all_invalid_flow_names = [] # Aggregate list of all invalid flow names
    logger.info(f"Scanning directory {src_main_mule_path} for Mule XML files.")
    
    xml_files_found = False
    for root_dir, _, files in os.walk(src_main_mule_path):
        for file in files:
            if file.endswith('.xml'):
                xml_files_found = True
                file_path = os.path.join(root_dir, file)
                logger.debug(f"Processing file: {file_path}")
                # count_flows_and_components now returns a tuple (counts, invalid_names)
                file_counts, invalid_names_in_file = count_flows_and_components(file_path)
                total_counts['flows'] += file_counts['flows']
                total_counts['sub_flows'] += file_counts['sub_flows']
                total_counts['components'] += file_counts['components']
                if invalid_names_in_file: # Only extend if the list is not empty
                    all_invalid_flow_names.extend(invalid_names_in_file)
    
    if not xml_files_found:
        logger.warning(f"No XML files found in {src_main_mule_path}. Counts will be zero.")

    flows_ok = total_counts['flows'] <= max_flows
    sub_flows_ok = total_counts['sub_flows'] <= max_sub_flows
    components_ok = total_counts['components'] <= max_components
    # Camel case validation status: True if no invalid names found
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
        'flow_names_camel_case_ok': flow_names_camel_case_ok, # New validation status
        'invalid_flow_names': all_invalid_flow_names,       # New list of invalid names
        'max_flows_limit': max_flows,
        'max_sub_flows_limit': max_sub_flows,
        'max_components_limit': max_components
    }
