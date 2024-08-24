import os
import yaml
from tabulate import tabulate

def validate_yaml_file(file_path):
    """
    Validates the YAML file at the given path.

    Args:
        file_path (str): The path to the YAML file to validate.

    Returns:
        tuple: (bool, str) - A tuple where the first element is a boolean indicating
               if the file is valid, and the second element is an error message
               if the file is invalid.
    """
    try:
        with open(file_path, 'r') as file:
            yaml.safe_load(file)
        return True, None
    except yaml.YAMLError as exc:
        return False, str(exc)

def validate_files(package_folder_path):
    """
    Validates the presence and syntax of YAML property files in the 
    src/main/resources directory of the given MuleSoft package folder path.

    Args:
        package_folder_path (str): The path to the MuleSoft package folder.
    """
    # Define mandatory and optional files
    mandatory_files = ['config-prod.yaml', 'config-nonprod.yaml']
    optional_files = ['config-dev.yaml', 'config-uat.yaml', 'config-local.yaml']
    
    # Build path to src/main/resources
    resources_folder_path = os.path.join(package_folder_path, 'src', 'main', 'resources')
    
    # Check if resources directory exists
    if not os.path.isdir(resources_folder_path):
        print(f"Error: The specified path does not exist: {resources_folder_path}")
        return
    
    # Collect results
    results = []
    all_files = mandatory_files + optional_files
    
    # Track if any files are found
    any_files_found = False

    for file_name in all_files:
        file_path = os.path.join(resources_folder_path, file_name)
        if os.path.isfile(file_path):
            any_files_found = True
            is_valid, error = validate_yaml_file(file_path)
            if file_name in mandatory_files:
                if not is_valid:
                    results.append([file_name, 'Invalid', error])
                else:
                    results.append([file_name, 'Valid', ''])
            elif file_name in optional_files:
                if not is_valid:
                    results.append([file_name, 'Invalid', error])
                else:
                    results.append([file_name, 'Valid', ''])
        elif file_name in mandatory_files:
            results.append([file_name, 'Missing', 'File not found'])

    # Print results only if any YAML files were found
    if any_files_found:
        print(tabulate(results, headers=['File Name', 'Status', 'Error'], tablefmt='grid'))

# Define the MuleSoft package folder path here
#package_folder_path = 'c:/work/rnd/mulesoft-temp/sbs-ott-triggerintegrator'
#package_folder_path = 'C:/Users/venkats/OneDrive - SBS Corporation/Documents/SBS/ws/mulesoft/' + 'sbs-mpx-mediamanagmentservices'
#package_folder_path = 'C:/Users/venkats/OneDrive - SBS Corporation/Documents/SBS/ws/mulesoft/' + 'sbs-tbs-ingestmediainfo'
#package_folder_path = 'C:/Users/venkats/OneDrive - SBS Corporation/Documents/SBS/ws/mulesoft/' + 'sbs-pnc-integrationservices'
package_folder_path = 'C:/Users/venkats/OneDrive - SBS Corporation/Documents/SBS/ws/mulesoft/' + 'sbs-eis-integrationservices'

# Validate the files in the specified package folder
validate_files(package_folder_path)
