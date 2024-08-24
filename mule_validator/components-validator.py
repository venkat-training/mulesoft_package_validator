import os
import xml.etree.ElementTree as ET
from tabulate import tabulate

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

    # Check for API specification files
    for root, _, files in os.walk(resources_path):
        for file in files:
            if file.endswith('.raml') or file.endswith('.yaml') or file.endswith('.json'):
                api_spec_files.append(os.path.join(root, file))

    # Check for API definition flows
    for root, _, files in os.walk(src_main_path):
        for file in files:
            if file.endswith('.xml'):
                file_path = os.path.join(root, file)
                try:
                    tree = ET.parse(file_path)
                    root_element = tree.getroot()

                    # Look for HTTP listener configs which typically indicate API flows
                    if root_element.find('.//{http://www.mulesoft.org/schema/mule/http}listener-config') is not None:
                        api_definition_flows.append(file_path)

                except ET.ParseError as e:
                    print(f"Error parsing XML file: {file_path} - {e}")

    return {'api_spec_files': api_spec_files, 'api_definition_flows': api_definition_flows}

def validate_mule_package(package_folder_path, max_flows=100, max_sub_flows=50, max_components=500):
    """
    Validates the number of flows, sub-flows, components, API specifications, and API definition flows in a MuleSoft package.

    Args:
        package_folder_path (str): The path to the MuleSoft package folder.
        max_flows (int): Maximum allowed number of flows.
        max_sub_flows (int): Maximum allowed number of sub-flows.
        max_components (int): Maximum allowed number of components.
    """
    src_main_path = os.path.join(package_folder_path, 'src', 'main')
    if not os.path.isdir(src_main_path):
        print(f"Error: The specified path does not exist: {src_main_path}")
        return
    
    total_counts = {'flows': 0, 'sub_flows': 0, 'components': 0}
    results = []

    # Iterate over all XML files in the src/main directory
    for root, _, files in os.walk(src_main_path):
        for file in files:
            if file.endswith('.xml'):
                file_path = os.path.join(root, file)
                file_counts = count_flows_and_components(file_path)
                total_counts['flows'] += file_counts['flows']
                total_counts['sub_flows'] += file_counts['sub_flows']
                total_counts['components'] += file_counts['components']
                results.append([file, file_counts['flows'], file_counts['sub_flows'], file_counts['components']])

    # Validate API specifications and definition flows
    api_validation_results = validate_api_spec_and_flows(package_folder_path)
    
    # Print detailed results for flows and components
    print(tabulate(results, headers=['File Name', 'Flows', 'Sub Flows', 'Components'], tablefmt='grid'))

    # Print total counts and validate against the limits
    print("\nTotal Counts:")
    print(f"Flows: {total_counts['flows']} (Max Allowed: {max_flows})")
    print(f"Sub Flows: {total_counts['sub_flows']} (Max Allowed: {max_sub_flows})")
    print(f"Components: {total_counts['components']} (Max Allowed: {max_components})")

    if total_counts['flows'] > max_flows:
        print("Warning: Number of flows exceeds the recommended limit!")

    if total_counts['sub_flows'] > max_sub_flows:
        print("Warning: Number of sub-flows exceeds the recommended limit!")

    if total_counts['components'] > max_components:
        print("Warning: Number of components exceeds the recommended limit!")

    # Print API specification and definition flow validation results
    print("\nAPI Specification Files Found:")
    if api_validation_results['api_spec_files']:
        for api_spec in api_validation_results['api_spec_files']:
            print(f"- {api_spec}")
    else:
        print("No API specification files found.")

    print("\nAPI Definition Flows Found:")
    if api_validation_results['api_definition_flows']:
        for api_flow in api_validation_results['api_definition_flows']:
            print(f"- {api_flow}")
    else:
        print("No API definition flows found.")

# Define the MuleSoft package folder path here
#package_folder_path = 'c:/work/rnd/mulesoft-temp/sbs-ott-triggerintegrator'
#package_folder_path = 'C:/Users/venkats/OneDrive - SBS Corporation/Documents/SBS/ws/mulesoft/' + 'sbs-mpx-mediamanagmentservices'
#package_folder_path = 'C:/Users/venkats/OneDrive - SBS Corporation/Documents/SBS/ws/mulesoft/' + 'sbs-tbs-ingestmediainfo'
#package_folder_path = 'C:/Users/venkats/OneDrive - SBS Corporation/Documents/SBS/ws/mulesoft/' + 'sbs-pnc-integrationservices'
package_folder_path = 'C:/Users/venkats/OneDrive - SBS Corporation/Documents/SBS/ws/mulesoft/' + 'sbs-eis-integrationservices'

# Validate the MuleSoft package
validate_mule_package(package_folder_path)
