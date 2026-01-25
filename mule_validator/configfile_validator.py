"""
Validates MuleSoft YAML configuration files.

This module checks for the presence of mandatory and optional YAML configuration
files within a MuleSoft project's `src/main/resources` directory. It also
validates the YAML syntax of these files and performs content-based checks
to identify potential issues, such as plaintext secrets, especially considering
whether the project utilizes Mule Secure Properties for encryption.

Additionally, it compares environment-specific configuration files (e.g., prod vs nonprod)
to detect keys that are expected to differ between environments (such as hostnames,
IP addresses, passwords, API endpoints, and URLs) but have identical values, which may
indicate a misconfiguration.
"""

import os
import yaml
import re

# Regex for detecting long, random-looking strings that might be unencrypted secrets.
# This pattern looks for strings of 32+ characters containing alphanumeric characters
# and common Base64 characters (+, /, =).
GENERIC_SECRET_PATTERN = re.compile(r'[a-zA-Z0-9+/=]{32,}')

# Keywords that often indicate a property key is for a sensitive value.
# Used to flag plaintext values for keys containing these terms.
SENSITIVE_KEYWORDS = ['password', 'secret', 'key', 'token', 'credentials', 'apikey']

def validate_yaml_file(file_path: str) -> tuple[bool, str | None]:
    """
    Validates the basic YAML syntax of a single file.

    Args:
        file_path (str): The path to the YAML file.

    Returns:
        tuple[bool, str | None]: A tuple where the first element is True if
        the YAML syntax is valid, False otherwise. The second element is a
        string containing the YAML parsing error message if invalid, or None if valid.
    """
    try:
        with open(file_path, 'r', encoding='utf-8') as file:
            yaml.safe_load(file)
        return True, None
    except yaml.YAMLError as exc:
        return False, str(exc)

def check_yaml_content_rules(file_path, project_uses_secure_properties):
    """
    Checks the content of a given YAML file for potential plaintext secrets or
    misconfigurations related to sensitive data.

    It uses a recursive helper to traverse nested YAML structures. Rules include:
    - Identifying Mule encrypted values (e.g., `![...]`).
    - Detecting values that match a generic pattern for secrets.
    - Checking keys containing sensitive keywords for plaintext values.

    The severity of reported issues (e.g., INFO vs. WARNING) can depend on whether
    the project is configured to use Mule Secure Properties. Values that appear to be
    filenames or paths are handled specially to reduce false positives for generic
    secret patterns or sensitive keywords.

    Args:
        file_path (str): The path to the YAML file to check.
        project_uses_secure_properties (bool): True if the MuleSoft project is
            configured to use Mule Secure Properties. This influences the advice
            given for plaintext sensitive values.

    Returns:
        list[str]: A list of issue description strings found in the YAML content.
                   Each string describes a potential problem.
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

            # Determine filename context
            key_lower = current_full_key_name.lower()
            is_key_suggestive_of_filename = any(suffix in key_lower for suffix in ['.filename', '.filepath', '.file', '.keyfile', '.certfile', '.configfile'])

            value_lower = value_str.lower()
            common_file_extensions = ('.jks', '.pem', '.cer', '.p12', '.keystore', '.properties', '.key', '.crt', '.yaml', '.yml', '.xml', '.json', '.txt')
            is_value_like_filename_or_path = value_lower.endswith(common_file_extensions) or '/' in value_str or '\\' in value_str or value_str.startswith("classpath:")

            is_filename_context = is_key_suggestive_of_filename or is_value_like_filename_or_path

            if is_mule_encrypted:
                # Value is Mule encrypted.
                if project_uses_secure_properties:
                    # This is expected and good practice if the project uses secure properties.
                    pass # Suppressing INFO message as per request
                else:
                    # This is unusual: value is encrypted, but no secure properties config was found project-wide.
                    issues.append(f"WARNING: Key '{current_full_key_name}' has a Mule encrypted value, but Mule Secure Properties configuration was not detected project-wide.")
            else:
                # Not Mule encrypted. Now check for other issues, considering filename context.

                # 1. Generic Secret Pattern Check
                # Check for generic secrets regardless of filename context, as filenames shouldn't look like secrets
                is_potential_generic_secret = GENERIC_SECRET_PATTERN.match(value_str)
                if is_potential_generic_secret:
                    issues.append(f"WARNING: Value for key '{current_full_key_name}' appears to be a generic secret/API key and is not Mule encrypted. Value excerpt: '{value_str[:10]}...'")

                # 2. Sensitive Keyword Check
                # Only apply if NOT in a filename context.
                # If key is "db.keyFile" and value is "path/to/file.key", this check should be skipped.
                # If key is "db.password" and value is "path/to/password.txt", this should also be skipped by is_filename_context.
                # If key is "db.password" and value is "actualPassword", this should NOT be skipped.
                if not is_filename_context:
                    for keyword in SENSITIVE_KEYWORDS:
                        if keyword in key_lower:
                            # The key name itself suggests sensitivity.
                            if project_uses_secure_properties:
                                issues.append(f"WARNING: Key '{current_full_key_name}' (contains sensitive keyword '{keyword}') has a plaintext value, but the project supports Mule encryption. Consider encrypting. Value excerpt: '{value_str[:10]}...'")
                            else:
                                issues.append(f"WARNING: Key '{current_full_key_name}' (contains sensitive keyword '{keyword}') may contain plaintext sensitive data, and the project does not appear to use Mule encryption. Value excerpt: '{value_str[:10]}...'")
                            break # Found one sensitive keyword match for this key

    _find_issues_in_yaml_data(data) # Start the recursive check from the root of the YAML data.
    return issues

# --- Start of new environment comparison logic ---

# TARGET_CONFIG_KEYWORDS: Defines keywords used to identify configuration properties
# that are expected to have environment-specific values. This list includes terms
# commonly found in keys for hostnames, IP addresses, credentials (passwords, secrets, API keys),
# instance identifiers, server names, user names, service URLs/URIs/endpoints, and ports.
# The comparison logic in `compare_environment_config_values` uses these keywords to filter
# which identical values across environments should be flagged as potential issues.
# Matching is case-insensitive and checks if any segment of a dot-separated key path
# contains one of these keywords.
TARGET_CONFIG_KEYWORDS = [
    'host', 'hostname', 'ip', 'ipaddress',
    'password', 'secret', 'key', 'apikey', 'token',
    'url', 'uri', 'endpoint'
]

# Regex pattern for strict environment-sensitive keys (edit as needed)
TARGET_CONFIG_REGEX = re.compile(
    r'^(host(name)?|ip(address)?|password|secret|apikey|token|url|uri|endpoint)$',
    re.IGNORECASE
)
# Note: The effectiveness of this list depends on common naming conventions.
# Keywords should be specific enough to target environment-sensitive properties
# while avoiding overly generic terms (e.g., 'name', 'id' alone) that might
# lead to false positives for properties that are legitimately common.

def _get_common_keys_with_identical_values(data1, data2, prefix=""):
    """
    Recursively finds common keys in two data structures (dicts) that have identical scalar values.

    Args:
        data1 (dict): The first dictionary (parsed YAML data) to compare.
        data2 (dict): The second dictionary (parsed YAML data) to compare.
        prefix (str): The current key path prefix, used for building full
                      dot-separated key paths during recursion.

    Returns:
        list[str]: A list of dot-separated key paths that exist in both `data1`
                   and `data2` and have identical scalar or list values.
    """
    identical_value_keys = []
    if not isinstance(data1, dict) or not isinstance(data2, dict):
        return identical_value_keys

    for key, value1 in data1.items():
        if key in data2:
            value2 = data2[key]
            current_key_path = f"{prefix}{key}"

            if isinstance(value1, dict) and isinstance(value2, dict):
                identical_value_keys.extend(
                    _get_common_keys_with_identical_values(value1, value2, prefix=f"{current_key_path}.")
                )
            # Compare if they are not dicts (i.e., scalars or lists - direct comparison)
            # We are interested if their direct values are the same.
            # For lists, this means the lists themselves must be identical.
            elif not isinstance(value1, dict) and not isinstance(value2, dict):
                if value1 == value2:
                    identical_value_keys.append(current_key_path)
            # If types are mixed (e.g., dict vs scalar), they are not considered "identical" in this context.
    return identical_value_keys

def compare_environment_config_values(env_configs_data):
    """
    Compares configuration data between different environments (e.g., prod vs. nonprod)
    to find keys that (a) have identical values and (b) are identified as
    potentially environment-specific based on TARGET_CONFIG_KEYWORDS or regex.

    Only keys whose segments match one of the `TARGET_CONFIG_KEYWORDS` or the
    `TARGET_CONFIG_REGEX` are considered for this comparison.

    Currently, this function specifically compares "prod" and "nonprod" environments
    if both are present in `env_configs_data`.

    Args:
        env_configs_data (dict[str, dict]): A dictionary where keys are environment
            identifiers (e.g., "prod", "nonprod") and values are their
            corresponding parsed YAML data (as dictionaries).

    Returns:
        list[str]: A list of issue description strings. Each string details a key
            that is (a) deemed environment-specific and (b) has an identical
            value in the compared environments (e.g., "prod" and "nonprod").
    """
    issues = []

    # Define pairs to compare. For now, focus on prod vs nonprod.
    comparison_pairs = []
    if "prod" in env_configs_data and "nonprod" in env_configs_data:
        comparison_pairs.append(("prod", "nonprod"))

    for env1_name, env2_name in comparison_pairs:
        env1_data = env_configs_data[env1_name]
        env2_data = env_configs_data[env2_name]

        if not env1_data or not env2_data:
            continue

        identical_raw_keys = _get_common_keys_with_identical_values(env1_data, env2_data)

        filtered_identical_keys = []
        for key_path in identical_raw_keys:
            key_path_segments = key_path.lower().split('.')
            is_relevant_key = False
            for segment in key_path_segments:
                # Only match if the segment is exactly a keyword or matches the regex
                if segment in TARGET_CONFIG_KEYWORDS or TARGET_CONFIG_REGEX.match(segment):
                    is_relevant_key = True
                    break
            if is_relevant_key:
                filtered_identical_keys.append(key_path)

        for key_path in filtered_identical_keys:
            issue_message = (
                f"WARNING: Key '{key_path}' (identified as potentially environment-specific) "
                f"has the same value in '{env1_name.upper()}' and '{env2_name.upper()}' configurations. "
                "These types of values should typically differ across environments."
            )
            issues.append(issue_message)

    return issues

def validate_files(package_folder_path, project_uses_secure_properties):
    """
    Validates YAML property files in a MuleSoft project's `src/main/resources` directory.

    This function checks for:
    1. Presence of mandatory files (`config-prod.yaml`, `config-nonprod.yaml`).
    2. YAML syntax validity of all found configuration files.
    3. Content rules violations (e.g., plaintext secrets) using `check_yaml_content_rules`.
    4. Environment comparison for specific keys (hostnames, IPs, passwords, URLs, endpoints, etc.)
       that should differ between environments.

    Args:
        package_folder_path (str): The path to the root of the MuleSoft package.
        project_uses_secure_properties (bool): A flag indicating whether the project
                                               is configured to use Mule Secure Properties.
                                               This affects how content rules are applied.
    Returns:
        list[list[str]]: A list of validation result entries. Each entry is a list of three strings:
            - `element_name` (str): The name of the file being validated or a description
              of the check (e.g., "Environment Comparison", "Prod vs NonProd Comparison").
            - `status` (str): A short description of the validation status or outcome
              (e.g., 'Missing', 'Invalid Syntax', 'Valid Syntax', 'Content Issue',
              'Environment Config Value Issue').
            - `message` (str): A detailed message describing the specific validation
              finding or issue. For 'Valid Syntax' or successful checks, this may be an empty string.
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

    parsed_env_configs_data = {} # To store parsed data for environment comparison
    
    all_files_to_check = mandatory_files + optional_files # Combine all files for iteration.
    
    for file_name in all_files_to_check:
        file_path = os.path.join(resources_folder_path, file_name)
        env_key_name = None # e.g. "prod" from "config-prod.yaml"

        # Try to extract env key from filename (e.g., "prod" from "config-prod.yaml")
        if file_name.startswith("config-") and file_name.endswith(".yaml"):
            parts = file_name[len("config-"):-len(".yaml")]
            if parts: # e.g. "prod", "nonprod", "dev"
                env_key_name = parts
        
        if os.path.isfile(file_path):
            # File exists, first validate its YAML syntax.
            is_valid_syntax, syntax_error_message = validate_yaml_file(file_path)
            
            if not is_valid_syntax:
                # If syntax is invalid, report it and do not proceed to content checks for this file.
                results.append([file_name, 'Invalid Syntax', syntax_error_message])
            else:
                # Syntax is valid. Record this and proceed to content rule checks.
                results.append([file_name, 'Valid Syntax', '']) 
                
                # Load YAML data for content checks and potential environment comparison
                try:
                    with open(file_path, 'r', encoding='utf-8') as f_env:
                        current_yaml_data = yaml.safe_load(f_env)
                    if env_key_name and current_yaml_data: # Store if data is not empty
                        parsed_env_configs_data[env_key_name] = current_yaml_data
                except Exception as e_load: # Catch potential errors during file read or parse for env comparison
                    results.append([file_name, 'Content Issue', f"ERROR: Could not load/parse {file_name} for env comparison: {e_load}"])
                    current_yaml_data = None # Ensure it's None if loading failed

                # Perform individual content rule checks (check_yaml_content_rules re-opens and parses)
                # This is slightly inefficient as we parse twice, but keeps check_yaml_content_rules self-contained.
                content_issues = check_yaml_content_rules(file_path, project_uses_secure_properties)
                for issue_message in content_issues:
                    results.append([file_name, 'Content Issue', issue_message])
                        
        elif file_name in mandatory_files:
            # If a mandatory file is missing, report it.
            results.append([file_name, 'Missing', 'Mandatory file not found'])

    # After checking all individual files, perform environment comparison
    if parsed_env_configs_data:
        env_comparison_issues = compare_environment_config_values(parsed_env_configs_data)
        for issue_message in env_comparison_issues:
            # Determine which files were involved for reporting (e.g. "Prod vs NonProd")
            # This is a bit tricky as compare_environment_config_values doesn't directly tell us.
            # We can infer from the issue message structure.
            report_file_ref = "Environment Comparison" # Default
            if "PROD" in issue_message and "NONPROD" in issue_message:
                report_file_ref = "Prod vs NonProd Comparison"
            elif "PROD" in issue_message and "DEV" in issue_message:
                 report_file_ref = "Prod vs Dev Comparison"
            # Add more specific refs if compare_environment_config_values is expanded

            results.append([report_file_ref, 'Environment Config Value Issue', issue_message])
            
    return results # Return the aggregated list of all findings.

# Example usage (typically called from main.py or a similar orchestrator script)
# package_folder_path = 'path/to/your/mulesoft/project'
#validate_files(package_folder_path)