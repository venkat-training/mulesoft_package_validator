"""
Validates API specifications and APIkit router configurations in MuleSoft projects.

This module checks for adherence to specific patterns for API specification inclusion
(as a RAML.zip dependency in pom.xml) and APIkit router setup within the Mule
application's XML configuration files.
"""
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
    Validates API specifications and APIkit router configurations in a MuleSoft package.

    This function checks for:
    1.  API specification dependency: Verifies that the API specification (RAML) is included
        as a specific Maven dependency (classifier "raml", type "zip") in the `pom.xml` file.
    2.  API specification artifact: Ensures the corresponding RAML ZIP artifact, generated from
        the dependency, is present in the `target/` directory, implying a successful build.
    3.  APIkit router configuration: Confirms that an APIkit router or configuration
        is defined within the expected Mule XML configuration file (e.g., `packagename.xml`)
        located in `src/main/mule/`.

    Assumptions:
        - The MuleSoft project follows a Maven-based structure.
        - The API specification is a RAML file, packaged as a ZIP.
        - A successful `mvn clean install` or equivalent build process populates the `target/` directory.
        - The main Mule configuration file containing the APIkit router is named after the package
          (e.g., if the package is `my-api`, the file is `my-api.xml`).

    Args:
        package_folder_path (str): The absolute or relative path to the root
            directory of the MuleSoft package.

    Returns:
        dict: A dictionary containing validation results:
            - 'api_spec_dependency' (str | None): The Maven dependency string for the API
              specification if found (e.g., "group:artifact:version:raml:zip"), otherwise None.
            - 'api_spec_zip_found' (bool): True if the RAML ZIP artifact is found in the
              `target/` directory, False otherwise.
            - 'apikit_router_file' (str | None): The name of the Mule configuration file
              expected to contain the APIkit router (e.g., "packagename.xml"), or the actual
              file name if found with a router. None if the primary expected file is not found.
            - 'apikit_router_found' (bool): True if an APIkit router or configuration
              is found in the identified Mule XML file, False otherwise.
            - 'notes' (list[str]): A list of human-readable messages detailing
              any validation failures or missing elements.
    """
    logger.info(f"Starting API spec and APIkit router validation for package: {package_folder_path}")
    validation_results = {
        'api_spec_dependency': None,
        'api_spec_zip_found': False,
        'apikit_router_file': None,
        'apikit_router_found': False,
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