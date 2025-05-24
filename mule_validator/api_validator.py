import os
import xml.etree.ElementTree as ET
import logging

# Configure logging
logger = logging.getLogger(__name__)

# Define constants
MULE_CORE_NAMESPACE_URI = "http://www.mulesoft.org/schema/mule/core"
SRC_MAIN_MULE_PATH_NAME = "src/main/mule"  # For Mule XML configuration files
API_SPECS_PATH_NAME = "src/main/resources/api"  # Common location for API specs
API_SPEC_EXTENSIONS = ('.raml', '.yaml', '.json')
API_DEFINITION_FLOW_NAME_MARKER = "api"

def validate_api_spec_and_flows(package_folder_path):
    """
    Validates the presence of API specifications and API definition flows in a MuleSoft package.

    Args:
        package_folder_path (str): The path to the MuleSoft package folder.

    Returns:
        dict: A dictionary containing the validation status of API specifications and definition flows.
    """
    logger.info(f"Starting API specification and definition flow validation for package: {package_folder_path}")
    validation_results = {
        'api_spec_files': [],
        'api_definition_flows': [],
        'api_spec_found': False,
        'api_definition_flow_found': False
    }

    # Construct the paths for API specs and Mule XMLs
    api_specs_dir = os.path.join(package_folder_path, API_SPECS_PATH_NAME)
    mule_xml_dir = os.path.join(package_folder_path, SRC_MAIN_MULE_PATH_NAME)

    # Collect API specification files
    logger.info(f"Scanning for API specification files in: {api_specs_dir}")
    if not os.path.isdir(api_specs_dir):
        logger.warning(f"API specification directory does not exist: {api_specs_dir}")
    else:
        for root_dir, _, files in os.walk(api_specs_dir):
            for file_name in files:
                if file_name.lower().endswith(API_SPEC_EXTENSIONS):
                    file_path = os.path.join(root_dir, file_name)
                    validation_results['api_spec_files'].append(file_path)
                    logger.debug(f"Found API specification file: {file_path}")
    
    if not validation_results['api_spec_files']:
        logger.warning(f"No API specification files found in {api_specs_dir}")

    # Collect API definition flows from Mule XML files
    logger.info(f"Scanning for API definition flows in Mule XML files in: {mule_xml_dir}")
    if not os.path.isdir(mule_xml_dir):
        logger.warning(f"Mule XML directory does not exist: {mule_xml_dir}")
    else:
        for root_dir, _, files in os.walk(mule_xml_dir):
            for file_name in files:
                if file_name.lower().endswith('.xml'):
                    file_path = os.path.join(root_dir, file_name)
                    logger.debug(f"Parsing XML file for API definition flows: {file_path}")
                    try:
                        tree = ET.parse(file_path)
                        xml_root = tree.getroot()
                        # Check for API definition flows in the XML
                        # Namespace dictionary for findall
                        namespaces = {'mule': MULE_CORE_NAMESPACE_URI}
                        for flow in xml_root.findall('.//mule:flow', namespaces=namespaces):
                            flow_name = flow.get('name', '').lower()
                            if API_DEFINITION_FLOW_NAME_MARKER in flow_name:
                                if file_path not in validation_results['api_definition_flows']: # Avoid duplicates
                                    validation_results['api_definition_flows'].append(file_path)
                                logger.debug(f"Found API definition flow '{flow_name}' in: {file_path}")
                                # No need to break, a file might have multiple relevant flows
                    except ET.ParseError as e:
                        logger.error(f"Error parsing XML file: {file_path} - {e}")
                    except FileNotFoundError:
                        logger.error(f"XML file not found during parsing (should not happen if os.walk succeeded): {file_path}")

    if not validation_results['api_definition_flows']:
        logger.warning(f"No API definition flows found in XML files under {mule_xml_dir}")

    # Update the status flags
    validation_results['api_spec_found'] = bool(validation_results['api_spec_files'])
    validation_results['api_definition_flow_found'] = bool(validation_results['api_definition_flows'])

    logger.info(f"API validation summary: Specs found: {validation_results['api_spec_found']}, Definition flows found: {validation_results['api_definition_flow_found']}")
    return validation_results