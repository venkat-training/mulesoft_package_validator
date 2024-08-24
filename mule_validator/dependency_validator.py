import os
import xml.etree.ElementTree as ET

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
        for dependency in root.findall(".//{http://maven.apache.org/POM/4.0.0}dependency"):
            group_id = dependency.find("{http://maven.apache.org/POM/4.0.0}groupId").text
            artifact_id = dependency.find("{http://maven.apache.org/POM/4.0.0}artifactId").text
            dependencies.append(f"{group_id}:{artifact_id}")
    except ET.ParseError as e:
        print(f"Error parsing POM file: {pom_file_path} - {e}")
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
    for root, _, files in os.walk(package_folder_path):
        for file in files:
            if file.endswith('.xml'):
                file_path = os.path.join(root, file)
                try:
                    with open(file_path, 'r') as f:
                        content = f.read()
                        for dependency in dependencies:
                            group_id, artifact_id = dependency.split(':')
                            if group_id in content or artifact_id in content:
                                used_dependencies.add(dependency)
                except Exception as e:
                    print(f"Error reading file: {file_path} - {e}")
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
        raise FileNotFoundError(f"POM file not found at path: {pom_file_path}")

    dependencies = parse_pom_dependencies(pom_file_path)
    used_dependencies = scan_code_for_dependencies(package_folder_path, dependencies)
    unused_dependencies = set(dependencies) - used_dependencies

    build_size_bytes = calculate_build_size(build_folder_path)
    build_size_mb = build_size_bytes / (1024 * 1024)
    size_status = build_size_mb <= max_size_mb

    return {
        'unused_dependencies': list(unused_dependencies),
        'build_size_mb': build_size_mb,
        'size_status': size_status
    }
