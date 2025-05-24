import os
import yaml
import logging

# Configure logging
logger = logging.getLogger(__name__)

# Define constants
RESOURCES_PATH_NAME = "src/main/resources"
MANDATORY_CONFIG_FILES = ['config-prod.yaml', 'config-nonprod.yaml']
OPTIONAL_CONFIG_FILES = ['config-dev.yaml', 'config-uat.yaml', 'config-local.yaml']

def validate_yaml_file(file_path):
    """
    Validates the YAML file at the given path.

    Args:
        file_path (str): The path to the YAML file to validate.

    Returns:
        tuple: (bool, str) - A tuple where the first element is a boolean indicating
               if the file is valid, and the second element is an error message
               if the file is invalid or cannot be opened.
    """
    logger.debug(f"Validating YAML file: {file_path}")
    try:
        with open(file_path, 'r', encoding='utf-8') as file:
            yaml.safe_load(file)
        logger.debug(f"YAML file is valid: {file_path}")
        return True, None
    except (IOError, OSError) as exc:
        error_message = f"Error opening or reading file: {exc}"
        logger.error(f"Error for file {file_path}: {error_message}")
        return False, error_message
    except yaml.YAMLError as exc:
        error_message = f"Invalid YAML syntax: {exc}"
        logger.error(f"Invalid YAML in file {file_path}: {error_message}")
        return False, error_message

def validate_files(package_folder_path):
    """
    Validates the presence and syntax of YAML property files in the
    src/main/resources directory of the given MuleSoft package folder path.

    Args:
        package_folder_path (str): The path to the MuleSoft package folder.

    Returns:
        list: A list of dictionaries, where each dictionary contains the validation
              result for a file (keys: 'file_name', 'status', 'message').
    """
    logger.info(f"Starting configuration file validation for package: {package_folder_path}")
    results = []
    
    resources_folder_path = os.path.join(package_folder_path, RESOURCES_PATH_NAME)
    logger.info(f"Checking for resources directory at: {resources_folder_path}")

    if not os.path.isdir(resources_folder_path):
        message = f"Resources directory not found at: {resources_folder_path}"
        logger.error(message)
        results.append({'file_name': 'N/A', 'status': 'Error', 'message': message})
        return results

    # Validate mandatory files
    logger.info(f"Validating mandatory files: {MANDATORY_CONFIG_FILES}")
    for file_name in MANDATORY_CONFIG_FILES:
        file_path = os.path.join(resources_folder_path, file_name)
        logger.debug(f"Checking mandatory file: {file_path}")
        if os.path.isfile(file_path):
            is_valid, error = validate_yaml_file(file_path)
            if not is_valid:
                results.append({'file_name': file_name, 'status': 'Invalid', 'message': error, 'type': 'Mandatory'})
            else:
                results.append({'file_name': file_name, 'status': 'Valid', 'message': '', 'type': 'Mandatory'})
        else:
            logger.warning(f"Mandatory file missing: {file_path}")
            results.append({'file_name': file_name, 'status': 'Missing', 'message': 'File not found', 'type': 'Mandatory'})

    # Validate optional files
    logger.info(f"Validating optional files: {OPTIONAL_CONFIG_FILES}")
    for file_name in OPTIONAL_CONFIG_FILES:
        file_path = os.path.join(resources_folder_path, file_name)
        logger.debug(f"Checking optional file: {file_path}")
        if os.path.isfile(file_path):
            is_valid, error = validate_yaml_file(file_path)
            if not is_valid:
                results.append({'file_name': file_name, 'status': 'Invalid', 'message': error, 'type': 'Optional'})
            else:
                results.append({'file_name': file_name, 'status': 'Valid', 'message': '', 'type': 'Optional'})
        else:
            # Optional files that are missing are not typically an error, just not present.
            # We can log this for information if desired, or simply not add them to results.
            logger.info(f"Optional file not found (this is not an error): {file_path}")
            # If you want to record their absence:
            # results.append({'file_name': file_name, 'status': 'Not Found', 'message': 'File not present', 'type': 'Optional'})


    logger.info(f"Configuration file validation completed. Results: {len(results)} files processed.")
    return results

# Example usage (can be removed or kept for testing)
# if __name__ == '__main__':
#     logging.basicConfig(level=logging.DEBUG) # Configure logging for testing
#     # Define the MuleSoft package folder path here
#     package_path = 'c:/work/rnd/mulesoft-temp/sbs-ott-triggerintegrator' 
#     # package_path = 'path_to_your_test_package' # Replace with a valid path for testing
#     validation_output = validate_files(package_path)
#     for item in validation_output:
#         print(item)
