import os
import xml.etree.ElementTree as ET
import logging

logger = logging.getLogger(__name__)

MULE_CORE_NAMESPACE_URI = "http://www.mulesoft.org/schema/mule/core"
APIKIT_NAMESPACE_URIS = [
    "http://www.mulesoft.org/schema/mule/apikit",
    "http://www.mulesoft.org/schema/mule/mule-apikit"
]
SRC_MAIN_MULE_PATH_NAME = "src/main/mule"
API_SPEC_DEP_CLASSIFIER = "raml"
API_SPEC_DEP_TYPE = "zip"

def validate_api_spec_and_flows(package_folder_path):
    """
    Validates the presence of API specifications and APIkit router configuration in a MuleSoft package,
    following the enterprise packaging pattern used by your company.

    - API spec is included as a dependency (raml.zip) in pom.xml (not as a JAR, not in src/main/resources/api).
    - The raml.zip file should be present in the target/ directory after a successful build.
    - APIkit router/config is defined in packagename.xml in src/main/mule.

    Args:
        package_folder_path (str): The path to the MuleSoft package folder.

    Returns:
        dict: Validation status of API spec dependency and APIkit router config, including notes for missing elements.
    """
    logger.info(f"Starting API spec and APIkit router validation for package: {package_folder_path}")
    validation_results = {
        'api_spec_dependency': None,      # The dependency string if found, else None
        'api_spec_zip_found': False,      # True if the raml.zip is found in target/
        'apikit_router_file': None,       # The Mule config file containing APIkit router, if found
        'apikit_router_found': False,     # True if APIkit router/config is found
        'notes': []
    }

    # 1. Check for API spec dependency in pom.xml
    pom_path = os.path.join(package_folder_path, "pom.xml")
    api_spec_dep = None
    api_spec_zip_name = None
    if os.path.isfile(pom_path):
        try:
            tree = ET.parse(pom_path)
            root = tree.getroot()
            ns = {'mvn': "http://maven.apache.org/POM/4.0.0"}
            for dep in root.findall(".//mvn:dependency", ns):
                classifier = dep.find("mvn:classifier", ns)
                dep_type = dep.find("mvn:type", ns)
                if classifier is not None and classifier.text == API_SPEC_DEP_CLASSIFIER and \
                   dep_type is not None and dep_type.text == API_SPEC_DEP_TYPE:
                    group_id = dep.find("mvn:groupId", ns)
                    artifact_id = dep.find("mvn:artifactId", ns)
                    version = dep.find("mvn:version", ns)
                    if group_id is not None and artifact_id is not None and version is not None:
                        api_spec_dep = f"{group_id.text}:{artifact_id.text}:{version.text}:{API_SPEC_DEP_CLASSIFIER}:{API_SPEC_DEP_TYPE}"
                        api_spec_zip_name = f"{artifact_id.text}-{version.text}-{API_SPEC_DEP_CLASSIFIER}.{API_SPEC_DEP_TYPE}"
                        break
        except Exception as e:
            logger.error(f"Error parsing pom.xml for API spec dependency: {e}")

    validation_results['api_spec_dependency'] = api_spec_dep

    # 2. Check for the raml.zip in the build/target directory
    api_spec_zip_found = False
    if api_spec_zip_name:
        target_dir = os.path.join(package_folder_path, "target")
        for root_dir, _, files in os.walk(target_dir):
            if api_spec_zip_name in files:
                api_spec_zip_found = True
                break
    validation_results['api_spec_zip_found'] = api_spec_zip_found

    if not api_spec_dep:
        validation_results['notes'].append(
            "No API spec dependency with classifier 'raml' and type 'zip' found in pom.xml."
        )
    elif not api_spec_zip_found:
        validation_results['notes'].append(
            f"API spec zip '{api_spec_zip_name}' not found in target/ after build. Ensure 'mvn clean install' was run."
        )

    # 3. Check for APIkit router/config in packagename.xml in src/main/mule
    mule_xml_dir = os.path.join(package_folder_path, SRC_MAIN_MULE_PATH_NAME)
    apikit_router_file = None
    apikit_router_found = False

    # Derive packagename from the folder name
    packagename = os.path.basename(os.path.abspath(package_folder_path))
    packagename_xml = f"{packagename}.xml"
    packagename_xml_path = os.path.join(mule_xml_dir, packagename_xml)

    if os.path.isfile(packagename_xml_path):
        try:
            tree = ET.parse(packagename_xml_path)
            xml_root = tree.getroot()
            apikit_router_file = None
            apikit_router_found = False
            # Search for apikit:router or apikit:config in all known APIkit namespaces
            for apikit_ns_uri in APIKIT_NAMESPACE_URIS:
                apikit_ns = {'apikit': apikit_ns_uri}
                router_found = xml_root.findall('.//apikit:router', namespaces=apikit_ns)
                config_found = xml_root.findall('.//apikit:config', namespaces=apikit_ns)
                if router_found or config_found:
                    apikit_router_file = packagename_xml
                    apikit_router_found = True
                    break
        except ET.ParseError as e:
            logger.error(f"Error parsing XML file: {packagename_xml_path} - {e}")
    else:
        validation_results['notes'].append(
            f"Expected APIkit router/config file '{packagename_xml}' not found in {SRC_MAIN_MULE_PATH_NAME}."
        )

    validation_results['apikit_router_file'] = apikit_router_file
    validation_results['apikit_router_found'] = apikit_router_found

    if not apikit_router_found:
        validation_results['notes'].append(
            f"No APIkit router/config found in '{packagename_xml}' in {SRC_MAIN_MULE_PATH_NAME}."
        )

    logger.info(
        f"API validation summary: Spec dependency: {bool(api_spec_dep)}, "
        f"Spec zip found: {api_spec_zip_found}, "
        f"APIkit router found: {apikit_router_found} (in {apikit_router_file})"
    )
    return validation_results