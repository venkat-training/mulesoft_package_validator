import os
import xml.etree.ElementTree as ET
import logging
import re
import subprocess
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

    for element in root.iter():
        element_tag_for_path = get_element_path(element)
        element_tag_lower = element_tag_for_path.lower()

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
            if not text_value:
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
            if isinstance(attr_value, str):
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
    Returns a list of (groupId, artifactId, version, classifier, dep_type) tuples.
    """
    dependencies = []
    try:
        tree = ET.parse(pom_file_path)
        root = tree.getroot()
        for dependency in root.findall(f".//{{{MAVEN_POM_NAMESPACE}}}dependency"):
            group_id = dependency.find(f"{{{MAVEN_POM_NAMESPACE}}}groupId")
            artifact_id = dependency.find(f"{{{MAVEN_POM_NAMESPACE}}}artifactId")
            version = dependency.find(f"{{{MAVEN_POM_NAMESPACE}}}version")
            classifier = dependency.find(f"{{{MAVEN_POM_NAMESPACE}}}classifier")
            dep_type = dependency.find(f"{{{MAVEN_POM_NAMESPACE}}}type")
            if group_id is not None and artifact_id is not None:
                dependencies.append((
                    group_id.text.strip(),
                    artifact_id.text.strip(),
                    version.text.strip() if version is not None and version.text else None,
                    classifier.text.strip() if classifier is not None and classifier.text else None,
                    dep_type.text.strip() if dep_type is not None and dep_type.text else "jar"
                ))
    except Exception as e:
        logger.error(f"Error parsing {pom_file_path}: {e}")
    return dependencies

def scan_code_for_dependencies(package_folder_path, dependencies):
    """
    Scans MuleSoft code for usages of dependencies.
    Args:
        package_folder_path (str): The path to the MuleSoft package folder.
        dependencies (list): List of dependency coordinates (groupId, artifactId, version, classifier, dep_type).
    Returns:
        set: A set of used dependencies.
    """
    used_dependencies = set()
    if not dependencies:
        return used_dependencies

    for root_dir, _, files in os.walk(package_folder_path):
        for file in files:
            if file.endswith('.xml'):
                file_path = os.path.join(root_dir, file)
                try:
                    with open(file_path, 'r', encoding='utf-8') as f:
                        content = f.read()
                        for dep in dependencies:
                            group_id, artifact_id = dep[0], dep[1]
                            if group_id in content or artifact_id in content:
                                used_dependencies.add(dep)
                except (IOError, OSError) as e:
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

def check_dependency_jars(target_folder, dependencies):
    """
    Checks if the dependency artifacts are present in the target or lib folder,
    or in the local Maven repository.
    Uses the correct extension based on <type>.
    Returns a list of missing artifacts.
    """
    missing_artifacts = []
    m2_repo = os.path.expanduser("~/.m2/repository")
    for group_id, artifact_id, version, classifier, dep_type in dependencies:
        if not version:
            continue
        ext = dep_type if dep_type != "jar" else "jar"
        if classifier:
            artifact_name = f"{artifact_id}-{version}-{classifier}.{ext}"
        else:
            artifact_name = f"{artifact_id}-{version}.{ext}"
        found = False
        # Check in target folder
        for root, dirs, files in os.walk(target_folder):
            if artifact_name in files:
                found = True
                break
        # Check in local Maven repository
        if not found:
            group_path = os.path.join(m2_repo, *group_id.split('.'), artifact_id, version)
            artifact_path = os.path.join(group_path, artifact_name)
            if os.path.isfile(artifact_path):
                found = True
        if not found:
            missing_artifacts.append(artifact_name)
    return missing_artifacts

def check_dependency_resolution(group_id, artifact_id, version, classifier=None, dep_type="jar"):
    """
    Checks if a dependency is resolvable by first looking in the local Maven repository,
    and only then using Maven to check remote repositories.
    Uses the correct extension based on <type>.
    Returns True if resolvable, False otherwise.
    """
    if not version:
        return False

    ext = dep_type if dep_type != "jar" else "jar"
    if classifier:
        artifact_name = f"{artifact_id}-{version}-{classifier}.{ext}"
    else:
        artifact_name = f"{artifact_id}-{version}.{ext}"
    m2_repo = os.path.expanduser("~/.m2/repository")
    group_path = os.path.join(m2_repo, *group_id.split('.'), artifact_id, version)
    artifact_path = os.path.join(group_path, artifact_name)
    if os.path.isfile(artifact_path):
        return True

    # If not found locally, try to resolve via Maven
    artifact_str = f"{group_id}:{artifact_id}:{version}"
    if classifier:
        artifact_str += f":{classifier}"
    if dep_type and dep_type != "jar":
        artifact_str += f"@{dep_type}"
    cmd = [
        r"C:\apps\apache-maven-3.9.9\bin\mvn.cmd", "dependency:get",
        f"-Dartifact={artifact_str}",
        "-q"
    ]
    try:
        result = subprocess.run(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=30)
        return result.returncode == 0
    except Exception as e:
        logger.error(f"Error running Maven for {artifact_str}: {e}")
        return False

def find_duplicate_dependencies(dependencies):
    """
    Finds duplicate dependencies (same groupId and artifactId and classifier and type).
    """
    seen = set()
    duplicates = set()
    for group_id, artifact_id, version, classifier, dep_type in dependencies:
        key = (group_id, artifact_id, classifier, dep_type)
        if key in seen:
            duplicates.add(key)
        else:
            seen.add(key)
    return [f"{g}:{a}" + (f":{c}" if c else "") + (f":{t}" if t and t != "jar" else "") for g, a, c, t in duplicates]

def validate_pom_dependencies(pom_file_path, target_folder):
    """
    Validates dependencies for a single pom.xml.
    Returns a dict with missing_jars, unresolved_deps, duplicate_deps.
    """
    results = {
        "missing_jars": [],
        "unresolved_dependencies": [],
        "duplicate_dependencies": [],
        "all_dependencies": []
    }
    dependencies = parse_pom_dependencies(pom_file_path)
    results["all_dependencies"] = dependencies

    # Check for missing artifacts in target/lib and local m2 repo
    missing_jars = check_dependency_jars(target_folder, dependencies)
    results["missing_jars"] = missing_jars

    # Check for unresolved dependencies via Maven
    unresolved = []
    for group_id, artifact_id, version, classifier, dep_type in dependencies:
        if not check_dependency_resolution(group_id, artifact_id, version, classifier, dep_type):
            unresolved.append(
                f"{group_id}:{artifact_id}:{version}" +
                (f":{classifier}" if classifier else "") +
                (f":{dep_type}" if dep_type and dep_type != "jar" else "")
            )
    results["unresolved_dependencies"] = unresolved

    # Check for duplicates
    duplicates = find_duplicate_dependencies(dependencies)
    results["duplicate_dependencies"] = duplicates

    return results

def validate_all_projects(base_folder):
    """
    Only validates the root-level pom.xml in the given base_folder.
    """
    validation_report = {}
    pom_path = os.path.join(base_folder, "pom.xml")
    target_folder = os.path.join(base_folder, "target")
    if os.path.isfile(pom_path):
        logger.info(f"Validating dependencies for {pom_path}")
        result = validate_pom_dependencies(pom_path, target_folder)
        validation_report[pom_path] = result
    else:
        logger.warning(f"No pom.xml found in {base_folder}")
    return validation_report