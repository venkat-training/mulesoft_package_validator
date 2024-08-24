import os
import xml.etree.ElementTree as ET

def count_flows_and_components(xml_file_path):
    """
    Parses a Mule XML file to count the number of flows, sub-flows, and components.
    Args:
        xml_file_path (str): Path to the XML file.
    Returns:
        dict: A dictionary containing counts for flows, sub-flows, and components.
    """
    counts = {'flows': 0, 'sub_flows': 0, 'components': 0}

    try:
        tree = ET.parse(xml_file_path)
        root = tree.getroot()

        # Count flows and sub-flows
        for flow in root.findall('.//{http://www.mulesoft.org/schema/mule/core}flow'):
            counts['flows'] += 1
            counts['components'] += len(flow)  # Count components within flows

        for sub_flow in root.findall('.//{http://www.mulesoft.org/schema/mule/core}sub-flow'):
            counts['sub_flows'] += 1
            counts['components'] += len(sub_flow)  # Count components within sub-flows

    except ET.ParseError as e:
        print(f"Error parsing XML file: {xml_file_path} - {e}")
    
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
    src_main_path = os.path.join(package_folder_path, 'src', 'main')
    if not os.path.isdir(src_main_path):
        raise FileNotFoundError(f"Directory does not exist: {src_main_path}")

    total_counts = {'flows': 0, 'sub_flows': 0, 'components': 0}
    for root, _, files in os.walk(src_main_path):
        for file in files:
            if file.endswith('.xml'):
                file_path = os.path.join(root, file)
                file_counts = count_flows_and_components(file_path)
                total_counts['flows'] += file_counts['flows']
                total_counts['sub_flows'] += file_counts['sub_flows']
                total_counts['components'] += file_counts['components']

    flow_status = total_counts['flows'] <= max_flows
    sub_flow_status = total_counts['sub_flows'] <= max_sub_flows
    component_status = total_counts['components'] <= max_components

    return {
        'total_counts': total_counts,
        'flow_status': flow_status,
        'sub_flow_status': sub_flow_status,
        'component_status': component_status
    }
