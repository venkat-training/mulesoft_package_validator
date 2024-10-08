import os
import xml.etree.ElementTree as ET

def validate_api_spec_and_flows(package_folder_path):
    """
    Validates the presence of API specifications and API definition flows in a MuleSoft package.

    Args:
        package_folder_path (str): The path to the MuleSoft package folder.

    Returns:
        dict: A dictionary containing the validation status of API specifications and definition flows.
    """
    validation_results = {
        'api_spec_files': [],
        'api_definition_flows': [],
        'spec_status': False,
        'definition_flow_status': False
    }

    # Construct the paths
    src_main_path = os.path.join(package_folder_path, 'src', 'main')
    resources_path = os.path.join(src_main_path, 'resources')
    
    # Validate the 'src/main' path
    if os.path.exists(src_main_path):
        print(f"Path exists: {src_main_path}")
    else:
        print(f"Path does not exist: {src_main_path}")

    # Validate the 'src/main/resources' path
    if os.path.exists(resources_path):
        print(f"Path exists: {resources_path}")
    else:
        print(f"Path does not exist: {resources_path}")
    
    # Collect API specification files
    print("API Validation resources_path:", resources_path)
    for root, _, files in os.walk(resources_path):
        for file in files:
            if isinstance(file, str) and (file.endswith('.raml') or file.endswith('.yaml') or file.endswith('.json')):
                file_path = os.path.join(root, file)
                validation_results['api_spec_files'].append(file_path)
    
    # Collect API definition flows from XML files
    for root, _, files in os.walk(src_main_path):
        for file in files:
            if isinstance(file, str) and file.endswith('.xml'):
                file_path = os.path.join(root, file)
                try:
                    tree = ET.parse(file_path)
                    xml_root = tree.getroot()
                    # Check for API definition flows in the XML
                    for flow in xml_root.findall('.//{http://www.mulesoft.org/schema/mule/core}flow'):
                        if 'api' in flow.get('name', '').lower():
                            validation_results['api_definition_flows'].append(file_path)
                except ET.ParseError as e:
                    print(f"Error parsing XML file: {file_path} - {e}")

    # Update the status flags
    validation_results['spec_status'] = bool(validation_results['api_spec_files'])
    validation_results['definition_flow_status'] = bool(validation_results['api_definition_flows'])

    return validation_results