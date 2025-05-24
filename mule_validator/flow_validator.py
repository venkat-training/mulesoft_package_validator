import os
import xml.etree.ElementTree as ET
import logging

# Configure logging
logger = logging.getLogger(__name__)

# Define constants
MULE_CORE_NAMESPACE_URI = "http://www.mulesoft.org/schema/mule/core"

def count_flows_and_components(xml_file_path):
    """
    Parses a Mule XML file to count the number of flows, sub-flows, and components.
    Args:
        xml_file_path (str): Path to the XML file.
    Returns:
        dict: A dictionary containing counts for flows, sub-flows, and components.
    """
    counts = {'flows': 0, 'sub_flows': 0, 'components': 0}
    logger.debug(f"Attempting to parse XML file: {xml_file_path}")
    try:
        # ET.parse handles opening the file, assuming default encoding or XML declaration specifies it.
        # For explicit encoding control with open(), it would be:
        # with open(xml_file_path, 'r', encoding='utf-8') as f:
        #     tree = ET.parse(f)
        tree = ET.parse(xml_file_path)
        root = tree.getroot()

        # Count flows and sub-flows
        for flow in root.findall(f'.//{{{MULE_CORE_NAMESPACE_URI}}}flow'):
            counts['flows'] += 1
            counts['components'] += len(flow)  # Count components within flows

        for sub_flow in root.findall(f'.//{{{MULE_CORE_NAMESPACE_URI}}}sub-flow'):
            counts['sub_flows'] += 1
            counts['components'] += len(sub_flow)  # Count components within sub-flows
        logger.debug(f"Successfully parsed {xml_file_path}: {counts}")

    except ET.ParseError as e:
        logger.error(f"Error parsing XML file: {xml_file_path} - {e}")
    except FileNotFoundError: # ET.parse can also raise this
        logger.error(f"XML file not found: {xml_file_path}")
    
    return counts

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
    logger.info(f"Scanning directory {src_main_mule_path} for Mule XML files.")
    
    xml_files_found = False
    for root_dir, _, files in os.walk(src_main_mule_path):
        for file in files:
            if file.endswith('.xml'):
                xml_files_found = True
                file_path = os.path.join(root_dir, file)
                logger.debug(f"Processing file: {file_path}")
                file_counts = count_flows_and_components(file_path)
                total_counts['flows'] += file_counts['flows']
                total_counts['sub_flows'] += file_counts['sub_flows']
                total_counts['components'] += file_counts['components']
    
    if not xml_files_found:
        logger.warning(f"No XML files found in {src_main_mule_path}. Counts will be zero.")

    flows_ok = total_counts['flows'] <= max_flows
    sub_flows_ok = total_counts['sub_flows'] <= max_sub_flows
    components_ok = total_counts['components'] <= max_components

    if not flows_ok:
        logger.warning(f"Flow count {total_counts['flows']} exceeds limit of {max_flows}.")
    if not sub_flows_ok:
        logger.warning(f"Sub-flow count {total_counts['sub_flows']} exceeds limit of {max_sub_flows}.")
    if not components_ok:
        logger.warning(f"Component count {total_counts['components']} exceeds limit of {max_components}.")

    return {
        'total_counts': total_counts,
        'flows_ok': flows_ok,
        'sub_flows_ok': sub_flows_ok,
        'components_ok': components_ok,
        'max_flows_limit': max_flows,
        'max_sub_flows_limit': max_sub_flows,
        'max_components_limit': max_components
    }
