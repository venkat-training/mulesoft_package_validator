import os
import yaml
import logging
import re
from mule_validator.security_patterns import (
    PASSWORD_KEYWORDS,
    COMMON_PASSWORD_PATTERNS,
    GENERIC_SECRET_KEYWORDS,
    GENERIC_SECRET_VALUE_PATTERNS
)

# Configure logging
logger = logging.getLogger(__name__)

# Define constants
RESOURCES_PATH_NAME = "src/main/resources"
MANDATORY_CONFIG_FILES = ['config-prod.yaml', 'config-nonprod.yaml']
OPTIONAL_CONFIG_FILES = ['config-dev.yaml', 'config-uat.yaml', 'config-local.yaml']

# Pre-compile regexes from security_patterns for efficiency
COMPILED_COMMON_PASSWORD_PATTERNS = [re.compile(p, re.IGNORECASE) for p in COMMON_PASSWORD_PATTERNS]
COMPILED_GENERIC_SECRET_VALUE_PATTERNS = [re.compile(p, re.IGNORECASE) for p in GENERIC_SECRET_VALUE_PATTERNS]
LOWERCASE_PASSWORD_KEYWORDS = [k.lower() for k in PASSWORD_KEYWORDS]
LOWERCASE_GENERIC_SECRET_KEYWORDS = [k.lower() for k in GENERIC_SECRET_KEYWORDS]


def find_secrets_in_yaml_data(data, current_path=""):
    """
    Recursively searches for hardcoded secrets in loaded YAML data.
    """
    issues = []
    if isinstance(data, dict):
        for key, value in data.items():
            new_path = f"{current_path}.{key}" if current_path else key
            key_lower = key.lower()

            if isinstance(value, str):
                # Check key keywords
                if key_lower in LOWERCASE_PASSWORD_KEYWORDS:
                    issues.append({
                        'path': new_path, 'key': key, 'value_excerpt': value[:50] + ('...' if len(value) > 50 else ''),
                        'issue_type': 'Hardcoded Secret', 'message': f"Key '{key}' matches a password keyword."
                    })
                elif key_lower in LOWERCASE_GENERIC_SECRET_KEYWORDS:
                    issues.append({
                        'path': new_path, 'key': key, 'value_excerpt': value[:50] + ('...' if len(value) > 50 else ''),
                        'issue_type': 'Hardcoded Secret', 'message': f"Key '{key}' matches a generic secret keyword."
                    })

                # Check value patterns
                for pattern_obj in COMPILED_COMMON_PASSWORD_PATTERNS:
                    if pattern_obj.search(value):
                        issues.append({
                            'path': new_path, 'key': key, 'value_excerpt': value[:50] + ('...' if len(value) > 50 else ''),
                            'issue_type': 'Suspicious Value', 'message': f"Value for key '{key}' matches common password pattern: {pattern_obj.pattern}"
                        })
                        # Do not break here, a value might match multiple patterns (e.g. keyword and value pattern)
                for pattern_obj in COMPILED_GENERIC_SECRET_VALUE_PATTERNS:
                    if pattern_obj.search(value):
                        issues.append({
                            'path': new_path, 'key': key, 'value_excerpt': value[:50] + ('...' if len(value) > 50 else ''),
                            'issue_type': 'Suspicious Value', 'message': f"Value for key '{key}' matches generic secret pattern: {pattern_obj.pattern}"
                        })
                        # Do not break here
            
            if isinstance(value, (dict, list)):
                issues.extend(find_secrets_in_yaml_data(value, new_path))
    elif isinstance(data, list):
        for index, item in enumerate(data):
            new_path = f"{current_path}[{index}]"
            if isinstance(item, str):
                # Only check value patterns for strings in lists, as there's no key.
                for pattern_obj in COMPILED_COMMON_PASSWORD_PATTERNS:
                    if pattern_obj.search(item):
                        issues.append({
                            'path': new_path, 'key': f"list_item_{index}", 'value_excerpt': item[:50] + ('...' if len(item) > 50 else ''),
                            'issue_type': 'Suspicious Value', 'message': f"List item at '{new_path}' matches common password pattern: {pattern_obj.pattern}"
                        })
                for pattern_obj in COMPILED_GENERIC_SECRET_VALUE_PATTERNS:
                    if pattern_obj.search(item):
                        issues.append({
                            'path': new_path, 'key': f"list_item_{index}", 'value_excerpt': item[:50] + ('...' if len(item) > 50 else ''),
                            'issue_type': 'Suspicious Value', 'message': f"List item at '{new_path}' matches generic secret pattern: {pattern_obj.pattern}"
                        })
            elif isinstance(item, (dict, list)):
                issues.extend(find_secrets_in_yaml_data(item, new_path))
    return issues


def validate_yaml_file(file_path):
    """
    Validates the YAML file at the given path for syntax and hardcoded secrets.

    Args:
        file_path (str): The path to the YAML file to validate.

    Returns:
        list: A list of dictionaries, where each dictionary contains validation
              results (syntax errors or security warnings).
    """
    logger.debug(f"Validating YAML file: {file_path}")
    results = []
    try:
        with open(file_path, 'r', encoding='utf-8') as file:
            data = yaml.safe_load(file)
        
        if data is None: # Handles empty or effectively empty (e.g. just comments) YAML files
            logger.debug(f"YAML file is empty or contains only comments: {file_path}")
            # Optionally, add a specific result for empty files if needed for reporting
            # results.append({'file_name': file_path, 'status': 'Empty', 'message': 'YAML file is empty or contains only comments.'})
            return results # No further validation needed for empty files

        logger.debug(f"YAML syntax is valid for: {file_path}. Checking for secrets...")
        secret_issues = find_secrets_in_yaml_data(data)
        for issue in secret_issues:
            results.append({
                'file_name': file_path,
                'status': 'SecurityWarning',
                'message': f"Potential secret at path '{issue['path']}'. Key: '{issue['key']}'. Type: {issue['issue_type']}. Description: {issue['message']}",
                'details': issue
            })
        
        if not results: # If no secrets found
             logger.debug(f"No hardcoded secrets found in: {file_path}")
             # No specific "Valid" message for secrets, absence of warnings implies validity in this context.
             # If a general "valid" entry is desired even with no secrets, it can be added here.

    except (IOError, OSError) as exc:
        error_message = f"Error opening or reading file: {exc}"
        logger.error(f"Error for file {file_path}: {error_message}")
        results.append({'file_name': file_path, 'status': 'Error', 'message': error_message})
    except yaml.YAMLError as exc:
        error_message = f"Invalid YAML syntax: {exc}"
        logger.error(f"Invalid YAML in file {file_path}: {error_message}")
        results.append({'file_name': file_path, 'status': 'InvalidSyntax', 'message': error_message})
    
    return results

def validate_files(package_folder_path):
    """
    Validates the presence and syntax of YAML property files, and checks for hardcoded secrets
    in the src/main/resources directory of the given MuleSoft package folder path.

    Args:
        package_folder_path (str): The path to the MuleSoft package folder.

    Returns:
        list: A list of dictionaries, where each dictionary contains the validation
              result for a file (keys: 'file_name', 'status', 'message', 'type', 'details' [optional]).
    """
    logger.info(f"Starting configuration file validation for package: {package_folder_path}")
    all_findings = []
    
    resources_folder_path = os.path.join(package_folder_path, RESOURCES_PATH_NAME)
    logger.info(f"Checking for resources directory at: {resources_folder_path}")

    if not os.path.isdir(resources_folder_path):
        message = f"Resources directory not found at: {resources_folder_path}"
        logger.error(message)
        all_findings.append({'file_name': 'N/A', 'status': 'Error', 'message': message, 'type': 'Setup'})
        return all_findings

    # Validate mandatory files
    logger.info(f"Validating mandatory files: {MANDATORY_CONFIG_FILES}")
    for file_name in MANDATORY_CONFIG_FILES:
        file_path = os.path.join(resources_folder_path, file_name)
        logger.debug(f"Checking mandatory file: {file_path}")
        if os.path.isfile(file_path):
            validation_results = validate_yaml_file(file_path)
            if not validation_results: # No syntax errors, no secrets
                 all_findings.append({'file_name': file_name, 'status': 'Valid', 'message': 'File is valid and no secrets detected.', 'type': 'Mandatory'})
            else:
                for res in validation_results:
                    # Add 'type' to each result dictionary before appending
                    res_copy = res.copy()
                    res_copy['type'] = 'Mandatory'
                    all_findings.append(res_copy)
        else:
            logger.warning(f"Mandatory file missing: {file_path}")
            all_findings.append({'file_name': file_name, 'status': 'Missing', 'message': 'File not found', 'type': 'Mandatory'})

    # Validate optional files
    logger.info(f"Validating optional files: {OPTIONAL_CONFIG_FILES}")
    for file_name in OPTIONAL_CONFIG_FILES:
        file_path = os.path.join(resources_folder_path, file_name)
        logger.debug(f"Checking optional file: {file_path}")
        if os.path.isfile(file_path):
            validation_results = validate_yaml_file(file_path)
            if not validation_results: # No syntax errors, no secrets
                 all_findings.append({'file_name': file_name, 'status': 'Valid', 'message': 'File is valid and no secrets detected.', 'type': 'Optional'})
            else:
                for res in validation_results:
                    res_copy = res.copy()
                    res_copy['type'] = 'Optional'
                    all_findings.append(res_copy)
        else:
            logger.info(f"Optional file not found (this is not an error): {file_path}")
            # Optionally, record their absence if needed for comprehensive reporting:
            # all_findings.append({'file_name': file_name, 'status': 'Not Found', 'message': 'File not present', 'type': 'Optional'})

    logger.info(f"Configuration file validation completed. Results: {len(all_findings)} findings.")
    return all_findings

# Example usage (can be removed or kept for testing)
# if __name__ == '__main__':
#     logging.basicConfig(level=logging.DEBUG, format='%(asctime)s - %(name)s - %(levelname)s - %(message)s')
#     # Create a dummy structure for testing
#     DUMMY_PACKAGE_PATH = "test_mule_package"
#     DUMMY_RESOURCES_PATH = os.path.join(DUMMY_PACKAGE_PATH, RESOURCES_PATH_NAME)
#     os.makedirs(DUMMY_RESOURCES_PATH, exist_ok=True)

#     # Create dummy config files
#     with open(os.path.join(DUMMY_RESOURCES_PATH, "config-prod.yaml"), "w", encoding="utf-8") as f:
#         yaml.dump({
#             "database": {"url": "jdbc:mysql://prod_server/db", "user": "prod_user", "password": "ProdPassword123!"},
#             "api_keys": {"google": "AIzaSy...", "service_secret": "super_secret_token_value"}
#         }, f)
    
#     with open(os.path.join(DUMMY_RESOURCES_PATH, "config-nonprod.yaml"), "w", encoding="utf-8") as f:
#         yaml.dump({"logging": {"level": "debug"}, "admin_pass": "admin"}, f) # Common weak password

#     with open(os.path.join(DUMMY_RESOURCES_PATH, "config-dev.yaml"), "w", encoding="utf-8") as f:
#         yaml.dump({"feature_flags": ["one", "two"], "developer_token": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c"},f) # JWT like token

#     with open(os.path.join(DUMMY_RESOURCES_PATH, "invalid-syntax.yaml"), "w", encoding="utf-8") as f: # Not in MANDATORY/OPTIONAL
#         f.write("key: value\n  bad_indent: here")
    
#     # Add to OPTIONAL_CONFIG_FILES for testing this specific file if needed, or test validate_yaml_file directly
#     # OPTIONAL_CONFIG_FILES.append("invalid-syntax.yaml") # Temporarily for testing via validate_files

#     logger.info("--- Running validation via validate_files ---")
#     validation_output = validate_files(DUMMY_PACKAGE_PATH)
#     for item in validation_output:
#         print(item)

#     logger.info("\n--- Running direct validation for invalid-syntax.yaml ---")
#     invalid_syntax_results = validate_yaml_file(os.path.join(DUMMY_RESOURCES_PATH, "invalid-syntax.yaml"))
#     for item in invalid_syntax_results:
#         print(item)
    
#     logger.info("\n--- Running direct validation for an empty file ---")
#     EMPTY_FILE_PATH = os.path.join(DUMMY_RESOURCES_PATH, "empty.yaml")
#     with open(EMPTY_FILE_PATH, "w", encoding="utf-8") as f:
#         f.write("# This is an empty yaml file with only comments")
#     empty_file_results = validate_yaml_file(EMPTY_FILE_PATH)
#     if not empty_file_results:
#         print(f"File '{EMPTY_FILE_PATH}' is considered valid and has no secrets.")
#     for item in empty_file_results:
#         print(item)

    # Clean up dummy files and directory
    # import shutil
    # shutil.rmtree(DUMMY_PACKAGE_PATH)
