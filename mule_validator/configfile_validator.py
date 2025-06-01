"""
Validates MuleSoft YAML configuration files.

This module checks for the presence of mandatory and optional YAML configuration
files within a MuleSoft project's `src/main/resources` directory. It also
validates the YAML syntax of these files and performs content-based checks
to identify potential issues, such as plaintext secrets, especially considering
whether the project utilizes Mule Secure Properties for encryption.
"""
import os
import yaml
import re
# tabulate is not used in this module directly anymore.
# It was likely used for printing results directly from this module before refactoring.
# from tabulate import tabulate 

def validate_yaml_file(file_path):
    """
    Validates the basic YAML syntax of a single file.

    Args:
        file_path (str): The path to the YAML file.

    Returns:
        tuple: A tuple `(is_valid, error_message)`.
               - `is_valid` (bool): True if the YAML syntax is valid, False otherwise.
               - `error_message` (str or None): A string containing the YAML parsing
                 error message if invalid, or None if valid.
    """
    try:
        with open(file_path, 'r', encoding='utf-8') as file: # Added encoding
            yaml.safe_load(file)
        return True, None
    except yaml.YAMLError as exc:
        return False, str(exc)

# Regex for detecting long, random-looking strings that might be unencrypted secrets.
# This pattern looks for strings of 32+ characters containing alphanumeric chars and common Base64 chars.
GENERIC_SECRET_PATTERN = re.compile(r'[a-zA-Z0-9+/=]{32,}')

# Keywords that often indicate a property key is for a sensitive value.
SENSITIVE_KEYWORDS = ['password', 'secret', 'key', 'token', 'credentials', 'apikey']

def check_yaml_content_rules(file_path, project_uses_secure_properties):
    """
    Checks the content of a given YAML file for potential plaintext secrets or
    misconfigurations related to sensitive data.

    It uses a recursive helper to traverse nested YAML structures. Rules include:
    - Identifying Mule encrypted values (e.g., `![...]`).
    - Detecting values that match a generic pattern for secrets.
    - Checking keys containing sensitive keywords for plaintext values.

    The severity of reported issues (INFO vs. WARNING) can depend on whether
    the project is configured to use Mule Secure Properties.

    Args:
        file_path (str): The path to the YAML file to check.
        project_uses_secure_properties (bool): True if the MuleSoft project is
                                               configured to use secure properties.

    Returns:
        list: A list of issue description strings found in the YAML content.
    """
    issues = []
    try:
        with open(file_path, 'r', encoding='utf-8') as file:
            data = yaml.safe_load(file)
    except Exception as e:
        # If the file cannot be read or parsed, report this as a critical error for content validation.
        issues.append(f"ERROR: Could not read or parse YAML file {file_path} for content validation: {e}")
        return issues

    if not data: # Handles empty or effectively empty (e.g., only comments) YAML files
        return issues # No data to check, so no content issues.

    def _find_issues_in_yaml_data(current_data, key_prefix=''):
        """
        Recursively traverses YAML data (dictionaries, lists, strings) to find issues.
        
        Args:
            current_data: The current piece of YAML data (dict, list, or scalar).
            key_prefix (str): The prefix for the current key, used to build full key paths
                              for reporting (e.g., "api.credentials.username.").
        """
        if isinstance(current_data, dict):
            # If it's a dictionary, iterate through its key-value pairs.
            for key, value in current_data.items():
                _find_issues_in_yaml_data(value, key_prefix + str(key) + ".")
        elif isinstance(current_data, list):
            # If it's a list, iterate through its items.
            for index, item in enumerate(current_data):
                _find_issues_in_yaml_data(item, key_prefix + str(index) + ".")
        elif isinstance(current_data, str):
            # If it's a string, apply the content validation rules.
            value_str = current_data
            # Construct the full key name for reporting (e.g., "db.password").
            current_full_key_name = key_prefix[:-1] if key_prefix.endswith('.') else key_prefix
            if not current_full_key_name: # Handle cases where a top-level value is a simple string
                 current_full_key_name = "UnnamedTopLevelValue"


            # Check if the value is Mule encrypted (starts with "![", ends with "]").
            is_mule_encrypted = value_str.startswith("![") and value_str.endswith("]")
            
            # Check if the value matches a generic pattern for secrets (long, random-looking string).
            is_potential_generic_secret = GENERIC_SECRET_PATTERN.match(value_str)

            if is_mule_encrypted:
                # Value is Mule encrypted.
                if project_uses_secure_properties:
                    # This is expected and good practice if the project uses secure properties.
                    # issues.append(f"INFO: Key '{current_full_key_name}' has a Mule encrypted value. Length (encrypted part): {len(value_str[2:-1])}.")
                    pass # Suppressing INFO message as per request
                else:
                    # This is unusual: value is encrypted, but no secure properties config was found project-wide.
                    # This might indicate a misconfiguration or an incomplete setup.
                    issues.append(f"WARNING: Key '{current_full_key_name}' has a Mule encrypted value, but Mule Secure Properties configuration was not detected project-wide.")
            elif is_potential_generic_secret:
                # Value is not Mule encrypted but matches a pattern that suggests it might be a secret.
                issues.append(f"WARNING: Value for key '{current_full_key_name}' appears to be a generic secret/API key and is not Mule encrypted. Value excerpt: '{value_str[:10]}...'")

            # Keyword-based check for sensitive data (only if not already Mule encrypted).
            # This avoids redundant warnings if a sensitive key is already properly encrypted.
            if not is_mule_encrypted:
                # Add filename check here
                value_lower = value_str.lower()
                # Define common file extensions
                file_extensions = ('.jks', '.pem', '.cer', '.p12', '.keystore', '.properties')
                is_filename = value_lower.endswith(file_extensions)

                if not is_filename: # Only proceed if it's not identified as a filename
                    key_lower = current_full_key_name.lower()
                    for keyword in SENSITIVE_KEYWORDS:
                        if keyword in key_lower:
                            # The key name itself suggests sensitivity (e.g., "password", "api.key").
                            if project_uses_secure_properties:
                                # Project supports encryption, but this specific sensitive key has a plaintext value.
                                issues.append(f"WARNING: Key '{current_full_key_name}' (contains sensitive keyword '{keyword}') has a plaintext value, but the project supports Mule encryption. Consider encrypting. Value excerpt: '{value_str[:10]}...'")
                            else:
                                # Project does not support encryption, and this sensitive key has a plaintext value. High risk.
                                issues.append(f"WARNING: Key '{current_full_key_name}' (contains sensitive keyword '{keyword}') may contain plaintext sensitive data, and the project does not appear to use Mule encryption. Value excerpt: '{value_str[:10]}...'")
                            break # Found one sensitive keyword match for this key, no need to check others.

    _find_issues_in_yaml_data(data) # Start the recursive check from the root of the YAML data.
    return issues

def validate_files(package_folder_path, project_uses_secure_properties):
    """
    Validates YAML property files in a MuleSoft project's `src/main/resources` directory.

    This function checks for:
    1. Presence of mandatory files (`config-prod.yaml`, `config-nonprod.yaml`).
    2. YAML syntax validity of all found configuration files.
    3. Content rules violations (e.g., plaintext secrets) using `check_yaml_content_rules`.

    Args:
        package_folder_path (str): The path to the root of the MuleSoft package.
        project_uses_secure_properties (bool): A flag indicating whether the project
                                               is configured to use Mule Secure Properties.
                                               This affects how content rules are applied.
    Returns:
        list: A list of validation results. Each result is a list of three elements:
              `[file_name, status, message]`.
              - `file_name` (str): The name of the YAML file.
              - `status` (str): Describes the validation status (e.g., 'Missing',
                'Invalid Syntax', 'Valid Syntax', 'Content Issue').
              - `message` (str): Detailed message about the issue or an empty string.
    """
    # Define standard YAML configuration files in MuleSoft projects.
    mandatory_files = ['config-prod.yaml', 'config-nonprod.yaml']
    optional_files = ['config-dev.yaml', 'config-uat.yaml', 'config-local.yaml']
    
    # Construct the path to the standard resources directory.
    resources_folder_path = os.path.join(package_folder_path, 'src', 'main', 'resources')
    
    results = [] # Initialize list to store all validation results.

    # Check if the resources directory actually exists.
    if not os.path.isdir(resources_folder_path):
        # If the resources directory is missing, report this and cannot proceed further.
        results.append(['N/A', 'Directory Missing', f"Resources directory not found: {resources_folder_path}"])
        return results 
    
    all_files_to_check = mandatory_files + optional_files # Combine all files for iteration.
    
    for file_name in all_files_to_check:
        file_path = os.path.join(resources_folder_path, file_name)
        
        if os.path.isfile(file_path):
            # File exists, first validate its YAML syntax.
            is_valid_syntax, syntax_error_message = validate_yaml_file(file_path)
            
            if not is_valid_syntax:
                # If syntax is invalid, report it and do not proceed to content checks for this file.
                results.append([file_name, 'Invalid Syntax', syntax_error_message])
            else:
                # Syntax is valid. Record this and proceed to content rule checks.
                results.append([file_name, 'Valid Syntax', '']) 
                
                content_issues = check_yaml_content_rules(file_path, project_uses_secure_properties)
                # Append each content issue found as a separate entry in the results.
                for issue_message in content_issues:
                    results.append([file_name, 'Content Issue', issue_message])
                        
        elif file_name in mandatory_files:
            # If a mandatory file is missing, report it.
            results.append([file_name, 'Missing', 'Mandatory file not found'])
            
    return results # Return the aggregated list of all findings.

# Example usage (typically called from main.py or a similar orchestrator script)
# package_folder_path = 'path/to/your/mulesoft/project'
#package_folder_path = 'C:/Users/venkats/OneDrive - SBS Corporation/Documents/SBS/ws/mulesoft/' + 'sbs-mpx-mediamanagmentservices'
#package_folder_path = 'C:/Users/venkats/OneDrive - SBS Corporation/Documents/SBS/ws/mulesoft/' + 'sbs-tbs-ingestmediainfo'
#package_folder_path = 'C:/Users/venkats/OneDrive - SBS Corporation/Documents/SBS/ws/mulesoft/' + 'sbs-pnc-integrationservices'
#package_folder_path = 'C:/Users/venkats/OneDrive - SBS Corporation/Documents/SBS/ws/mulesoft/' + 'sbs-eis-integrationservices'

# Validate the files in the specified package folder
#validate_files(package_folder_path)
