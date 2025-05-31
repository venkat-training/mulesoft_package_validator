import os
import xml.etree.ElementTree as ET
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
MAVEN_POM_NAMESPACE = "http://maven.apache.org/POM/4.0.0"

# Pre-compile regexes and prepare keywords
COMPILED_COMMON_PASSWORD_PATTERNS = [re.compile(p, re.IGNORECASE) for p in COMMON_PASSWORD_PATTERNS]
COMPILED_GENERIC_SECRET_VALUE_PATTERNS = [re.compile(p, re.IGNORECASE) for p in GENERIC_SECRET_VALUE_PATTERNS]
LOWERCASE_PASSWORD_KEYWORDS = [k.lower() for k in PASSWORD_KEYWORDS]
LOWERCASE_GENERIC_SECRET_KEYWORDS = [k.lower() for k in GENERIC_SECRET_KEYWORDS]


def get_element_path(element):
    """
    Generates a simplified path for an XML element, primarily its tag.
    Removes namespace for brevity.
    """
    if element is None:
        return "UnknownElement"
    tag_name = element.tag
    if '}' in tag_name:
        tag_name = tag_name.split('}', 1)[-1]
    return tag_name


def find_secrets_in_pom_xml(root, pom_file_path):
    """
    Traverses the XML tree of a POM file and checks for hardcoded secrets
    in element tags, text content, and attribute names/values.
    """
    issues = []
    if root is None:
        return issues

    for element in root.iter(): # Iterates over all elements in the tree
        element_tag_for_path = get_element_path(element)
        element_tag_lower = element_tag_for_path.lower() # Use the simplified tag name for checks

        # 1. Check element tag name
        if element_tag_lower in LOWERCASE_PASSWORD_KEYWORDS and element.text:
            issues.append({
                'file_path': pom_file_path, 'xml_path': element_tag_for_path, 'element_tag': element.tag,
                'attribute_name': None, 'value_excerpt': (element.text or "")[:50] + ('...' if len(element.text or "") > 50 else ''),
                'issue_type': 'Hardcoded Secret',
                'message': f"Element tag <{element_tag_for_path}> matches a password keyword and contains text."
            })
        elif element_tag_lower in LOWERCASE_GENERIC_SECRET_KEYWORDS and element.text:
            issues.append({
                'file_path': pom_file_path, 'xml_path': element_tag_for_path, 'element_tag': element.tag,
                'attribute_name': None, 'value_excerpt': (element.text or "")[:50] + ('...' if len(element.text or "") > 50 else ''),
                'issue_type': 'Hardcoded Secret',
                'message': f"Element tag <{element_tag_for_path}> matches a generic secret keyword and contains text."
            })

        # 2. Check element text content
        if element.text and isinstance(element.text, str):
            text_value = element.text.strip()
            if not text_value: # Skip if text is just whitespace
                continue
            for pattern_obj in COMPILED_COMMON_PASSWORD_PATTERNS:
                if pattern_obj.search(text_value):
                    issues.append({
                        'file_path': pom_file_path, 'xml_path': element_tag_for_path, 'element_tag': element.tag,
                        'attribute_name': None, 'value_excerpt': text_value[:50] + ('...' if len(text_value) > 50 else ''),
                        'issue_type': 'Suspicious Value',
                        'message': f"Text content of <{element_tag_for_path}> matches common password pattern: {pattern_obj.pattern}"
                    })
            for pattern_obj in COMPILED_GENERIC_SECRET_VALUE_PATTERNS:
                if pattern_obj.search(text_value):
                    issues.append({
                        'file_path': pom_file_path, 'xml_path': element_tag_for_path, 'element_tag': element.tag,
                        'attribute_name': None, 'value_excerpt': text_value[:50] + ('...' if len(text_value) > 50 else ''),
                        'issue_type': 'Suspicious Value',
                        'message': f"Text content of <{element_tag_for_path}> matches generic secret pattern: {pattern_obj.pattern}"
                    })
        
        # 3. Check attributes
        for attr_name, attr_value in element.attrib.items():
            attr_name_lower = attr_name.lower()
            if isinstance(attr_value, str): # Ensure attribute value is a string
                # Check attribute name keywords
                if attr_name_lower in LOWERCASE_PASSWORD_KEYWORDS:
                    issues.append({
                        'file_path': pom_file_path, 'xml_path': element_tag_for_path, 'element_tag': element.tag,
                        'attribute_name': attr_name, 'value_excerpt': attr_value[:50] + ('...' if len(attr_value) > 50 else ''),
                        'issue_type': 'Hardcoded Secret',
                        'message': f"Attribute '{attr_name}' in <{element_tag_for_path}> matches a password keyword."
                    })
                elif attr_name_lower in LOWERCASE_GENERIC_SECRET_KEYWORDS:
                     issues.append({
                        'file_path': pom_file_path, 'xml_path': element_tag_for_path, 'element_tag': element.tag,
                        'attribute_name': attr_name, 'value_excerpt': attr_value[:50] + ('...' if len(attr_value) > 50 else ''),
                        'issue_type': 'Hardcoded Secret',
                        'message': f"Attribute '{attr_name}' in <{element_tag_for_path}> matches a generic secret keyword."
                    })

                # Check attribute value patterns
                for pattern_obj in COMPILED_COMMON_PASSWORD_PATTERNS:
                    if pattern_obj.search(attr_value):
                        issues.append({
                            'file_path': pom_file_path, 'xml_path': element_tag_for_path, 'element_tag': element.tag,
                            'attribute_name': attr_name, 'value_excerpt': attr_value[:50] + ('...' if len(attr_value) > 50 else ''),
                            'issue_type': 'Suspicious Value',
                            'message': f"Value of attribute '{attr_name}' in <{element_tag_for_path}> matches common password pattern: {pattern_obj.pattern}"
                        })
                for pattern_obj in COMPILED_GENERIC_SECRET_VALUE_PATTERNS:
                    if pattern_obj.search(attr_value):
                        issues.append({
                            'file_path': pom_file_path, 'xml_path': element_tag_for_path, 'element_tag': element.tag,
                            'attribute_name': attr_name, 'value_excerpt': attr_value[:50] + ('...' if len(attr_value) > 50 else ''),
                            'issue_type': 'Suspicious Value',
                            'message': f"Value of attribute '{attr_name}' in <{element_tag_for_path}> matches generic secret pattern: {pattern_obj.pattern}"
                        })
    return issues


def parse_pom_dependencies(pom_file_path):
    """
    Parses the Maven POM file to extract dependencies.
    Args:
        pom_file_path (str): The path to the pom.xml file.
    Returns:
        tuple: (list of dependencies, ET.Element root object or None)
    """
    dependencies = []
    root = None
    try:
        tree = ET.parse(pom_file_path)
        root = tree.getroot()

        # Find all dependencies
        for dependency in root.findall(f".//{{{MAVEN_POM_NAMESPACE}}}dependency"):
            group_id_element = dependency.find(f"{{{MAVEN_POM_NAMESPACE}}}groupId")
            artifact_id_element = dependency.find(f"{{{MAVEN_POM_NAMESPACE}}}artifactId")
            if group_id_element is not None and artifact_id_element is not None:
                group_id = group_id_element.text
                artifact_id = artifact_id_element.text
                dependencies.append(f"{group_id}:{artifact_id}")
            else:
                logger.warning(f"Found a dependency without groupId or artifactId in {pom_file_path}")
    except ET.ParseError as e:
        logger.error(f"Error parsing POM file: {pom_file_path} - {e}")
    return dependencies, root

def scan_code_for_dependencies(package_folder_path, dependencies):
    """
    Scans MuleSoft code for usages of dependencies.
    Args:
        package_folder_path (str): The path to the MuleSoft package folder.
        dependencies (list): List of dependency coordinates (groupId:artifactId).
    Returns:
        set: A set of used dependencies.
    """
    used_dependencies = set()
    if not dependencies: # No need to scan if there are no dependencies to look for
        return used_dependencies

    for root_dir, _, files in os.walk(package_folder_path):
        for file in files:
            if file.endswith('.xml'): # Assuming Mule configuration files are XML
                file_path = os.path.join(root_dir, file)
                try:
                    with open(file_path, 'r', encoding='utf-8') as f: # Specify encoding
                        content = f.read()
                        for dependency in dependencies:
                            # Simple check, could be refined for more accuracy
                            # e.g., by checking for specific XML elements or patterns
                            group_id, artifact_id = dependency.split(':', 1) # Split only once
                            if group_id in content or artifact_id in content:
                                used_dependencies.add(dependency)
                except (IOError, OSError) as e: # Catch more specific exceptions
                    logger.error(f"Error reading or processing file: {file_path} - {e}")
    return used_dependencies

def calculate_build_size(build_folder_path):
    """
    Calculates the total size of the build directory.
    Args:
        build_folder_path (str): The path to the build folder (e.g., target).
    Returns:
        int: Total size in bytes.
    """
    total_size = 0
    for dirpath, _, filenames in os.walk(build_folder_path):
        for filename in filenames:
            file_path = os.path.join(dirpath, filename)
            total_size += os.path.getsize(file_path)
    return total_size

def validate_dependencies_and_size(package_folder_path, build_folder_path, max_size_mb=100):
    """
    Validates dependencies and build size for a MuleSoft package.
    Args:
        package_folder_path (str): The path to the MuleSoft package folder.
        build_folder_path (str): The path to the build folder (e.g., target).
        max_size_mb (int): Maximum allowed size in MB for the build.
    Returns:
        dict: Validation results including unused dependencies, build size status, and pom security warnings.
    """
    pom_file_path = os.path.join(package_folder_path, 'pom.xml')
    results = {
        'unused_dependencies': [],
        'build_size_mb': 0,
        'size_ok': False, # Default to false, set to true if size is ok or not calculable
        'max_size_mb': max_size_mb,
        'pom_security_warnings': [],
        'pom_parsing_error': None
    }

    if not os.path.isfile(pom_file_path):
        logger.error(f"POM file not found at path: {pom_file_path}")
        # Raising FileNotFoundError as per requirements for this specific error.
        # Other errors (like parsing) will be reported in the results dict.
        raise FileNotFoundError(f"POM file not found at path: {pom_file_path}")

    dependencies, pom_root = parse_pom_dependencies(pom_file_path)
    if pom_root is None: # Indicates a parsing error
        logger.error(f"POM file parsing failed for {pom_file_path}. Secret scanning will be skipped.")
        results['pom_parsing_error'] = f"Could not parse {pom_file_path}. Secret scanning skipped."
    else:
        logger.info(f"Successfully parsed {pom_file_path}. Scanning for secrets...")
        secret_issues = find_secrets_in_pom_xml(pom_root, pom_file_path)
        results['pom_security_warnings'] = secret_issues
        if secret_issues:
            logger.warning(f"Found {len(secret_issues)} potential secrets in {pom_file_path}.")
        else:
            logger.info(f"No potential secrets found in {pom_file_path}.")

    if not dependencies and pom_root is not None: # POM parsed but no dependencies found
        logger.warning(f"No dependencies found in {pom_file_path}.")
    elif not dependencies and pom_root is None: # POM parsing failed, already logged
        logger.warning(f"Proceeding with empty dependency list due to POM parsing issues or empty POM for {pom_file_path}.")


    used_dependencies = scan_code_for_dependencies(package_folder_path, dependencies)
    unused_dependencies = set(dependencies) - used_dependencies
    results['unused_dependencies'] = list(unused_dependencies)

    if unused_dependencies:
        logger.warning(f"Unused dependencies found: {list(unused_dependencies)}")

    build_size_bytes = 0
    try:
        build_size_bytes = calculate_build_size(build_folder_path)
        build_size_mb = build_size_bytes / (1024 * 1024)
        results['build_size_mb'] = round(build_size_mb, 2)
        results['size_ok'] = build_size_mb <= max_size_mb

        if not results['size_ok']:
            logger.warning(f"Build size {build_size_mb:.2f}MB exceeds maximum of {max_size_mb}MB.")
        else:
            logger.info(f"Build size {build_size_mb:.2f}MB is within the limit of {max_size_mb}MB.")
    except OSError as e:
        logger.error(f"Could not calculate build size for {build_folder_path}: {e}")
        # results['size_ok'] remains False or could be set to a specific error status
        results['build_size_error'] = f"Could not calculate build size: {e}"
        results['size_ok'] = False # Explicitly set to false on error


    return results
