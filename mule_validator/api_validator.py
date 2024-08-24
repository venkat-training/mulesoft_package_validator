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
    src_main_path = os.path.join(package_folder_path, 'src', 'main')
    resources_path = os.path.join(src_main_path, 'resources')
    api_spec_files = []
    api_definition_flows = []

    for root, _, files in os.walk(resources_path):
        for file in files:
            if file.endswith('.raml') or file.endswith('.yaml') or file.endswith('.json'):
                api_spec_files.append(os.path.join(root, file))

    for root, _, files in os.walk(src_main_path):
        for file in files:
            if file.endswith('.xml'):
                file_path = os.path.join(root, file)
                try:
                    tree = ET.parse(file_path)
                    root = tree.getroot()
                    # Check for API definition flows in the XML
                    for flow in root.findall('.//{http://www.mulesoft.org/schema/mule/core}flow'):
                        if 'api' in flow.get('name', '').lower():
                            api_definition_flows.append(file_path)
                except ET.ParseError as e:
                    print(f"Error parsing XML file: {file_path} - {e}")

    return {
        'api_spec_files': api_spec_files,
        'api_definition_flows': api_definition_flows,
        'spec_status': bool(api_spec_files),
        'definition_flow_status': bool(api_definition_flows)
    }
