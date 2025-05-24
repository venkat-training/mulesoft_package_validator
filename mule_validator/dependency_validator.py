import os
import xml.etree.ElementTree as ET
import logging

# Configure logging
logger = logging.getLogger(__name__)

# Define constants
MAVEN_POM_NAMESPACE = "http://maven.apache.org/POM/4.0.0"

def parse_pom_dependencies(pom_file_path):
    """
    Parses the Maven POM file to extract dependencies.
    Args:
        pom_file_path (str): The path to the pom.xml file.
    Returns:
        list: A list of dependency coordinates (groupId:artifactId).
    """
    dependencies = []
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
    return dependencies

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
        dict: Validation results including unused dependencies and build size status.
    """
    pom_file_path = os.path.join(package_folder_path, 'pom.xml')
    if not os.path.isfile(pom_file_path):
        logger.error(f"POM file not found at path: {pom_file_path}")
        # Raising FileNotFoundError is important as per requirements
        raise FileNotFoundError(f"POM file not found at path: {pom_file_path}")

    dependencies = parse_pom_dependencies(pom_file_path)
    if not dependencies and not os.path.isfile(pom_file_path): # If pom parsing failed and file doesn't exist (already logged)
        pass # Or handle as a critical error, though parse_pom_dependencies already logged it.
    elif not dependencies:
        logger.warning(f"No dependencies found or POM parsing failed for {pom_file_path}. Proceeding with empty dependency list.")


    used_dependencies = scan_code_for_dependencies(package_folder_path, dependencies)
    unused_dependencies = set(dependencies) - used_dependencies

    if unused_dependencies:
        logger.warning(f"Unused dependencies found: {list(unused_dependencies)}")

    build_size_bytes = 0
    try:
        build_size_bytes = calculate_build_size(build_folder_path)
    except OSError as e:
        logger.error(f"Could not calculate build size for {build_folder_path}: {e}")
        # Depending on requirements, might want to return a specific error state or re-raise

    build_size_mb = build_size_bytes / (1024 * 1024)
    size_ok = build_size_mb <= max_size_mb

    if not size_ok:
        logger.warning(f"Build size {build_size_mb:.2f}MB exceeds maximum of {max_size_mb}MB.")
    else:
        logger.info(f"Build size {build_size_mb:.2f}MB is within the limit of {max_size_mb}MB.")


    return {
        'unused_dependencies': list(unused_dependencies),
        'build_size_mb': round(build_size_mb, 2), # Round for cleaner output
        'size_ok': size_ok, # Renamed for clarity from 'size_status'
        'max_size_mb': max_size_mb
    }
