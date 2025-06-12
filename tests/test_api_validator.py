import unittest
from unittest.mock import patch, MagicMock, mock_open
import os
import xml.etree.ElementTree as ET
import sys

# Add the parent directory of 'mule_validator' to the Python path
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

from mule_validator import api_validator # Import the module

# Define constants from the module for easier use in tests, if needed
MULE_CORE_NAMESPACE_URI = "http://www.mulesoft.org/schema/mule/core"
APIKIT_NAMESPACE_URIS = [
    "http://www.mulesoft.org/schema/mule/apikit",
    "http://www.mulesoft.org/schema/mule/mule-apikit"
]
SRC_MAIN_MULE_PATH_NAME = "src/main/mule"
API_SPEC_DEP_CLASSIFIER = "raml"
API_SPEC_DEP_TYPE = "zip"


class TestApiValidator(unittest.TestCase):

    def _create_mock_pom_xml_tree(self, has_raml_dependency=True, group_id="com.example", artifact_id="my-api-spec", version="1.0.0"):
        if has_raml_dependency:
            pom_xml_content = f"""
            <project xmlns="http://maven.apache.org/POM/4.0.0">
                <dependencies>
                    <dependency>
                        <groupId>{group_id}</groupId>
                        <artifactId>{artifact_id}</artifactId>
                        <version>{version}</version>
                        <classifier>{API_SPEC_DEP_CLASSIFIER}</classifier>
                        <type>{API_SPEC_DEP_TYPE}</type>
                    </dependency>
                </dependencies>
            </project>
            """
        else:
            pom_xml_content = """
            <project xmlns="http://maven.apache.org/POM/4.0.0">
                <dependencies></dependencies>
            </project>
            """
        return ET.fromstring(pom_xml_content)

    def _create_mock_mule_config_xml_tree(self, has_apikit_router=True, apikit_ns_index=0):
        apikit_ns_uri_to_use = APIKIT_NAMESPACE_URIS[apikit_ns_index]
        if has_apikit_router:
            # Note the correct namespace prefixing for elements and attributes if necessary
            mule_xml_content = f"""
            <mule xmlns="http://www.mulesoft.org/schema/mule/core"
                  xmlns:apikit="{apikit_ns_uri_to_use}">
                <flow name="api-main">
                    <apikit:router config-ref="api-config"/>
                </flow>
                <apikit:config name="api-config" raml="api.raml"/>
            </mule>
            """
        else:
            mule_xml_content = """
            <mule xmlns="http://www.mulesoft.org/schema/mule/core">
                <flow name="some-flow">
                    <logger message="Hello"/>
                </flow>
            </mule>
            """
        return ET.fromstring(mule_xml_content)

    @patch('os.path.isfile')
    @patch('xml.etree.ElementTree.parse')
    @patch('os.walk')
    @patch('os.path.basename')
    @patch('os.path.abspath')
    def test_all_conditions_met(self, mock_abspath, mock_basename, mock_os_walk, mock_et_parse, mock_isfile):
        project_path = "/dummy/project/my-mule-project"
        mock_abspath.return_value = project_path # Ensure abspath returns what's expected
        mock_basename.return_value = "my-mule-project"

        # Simulate pom.xml and packagename.xml exist
        def isfile_side_effect(path):
            if path == os.path.join(project_path, "pom.xml"):
                return True
            if path == os.path.join(project_path, SRC_MAIN_MULE_PATH_NAME, "my-mule-project.xml"):
                return True
            return False
        mock_isfile.side_effect = isfile_side_effect

        # Mock ET.parse for pom.xml and mule config
        mock_pom_tree = MagicMock()
        mock_pom_tree.getroot.return_value = self._create_mock_pom_xml_tree()

        mock_mule_config_tree = MagicMock()
        mock_mule_config_tree.getroot.return_value = self._create_mock_mule_config_xml_tree()

        def et_parse_side_effect(path):
            if path == os.path.join(project_path, "pom.xml"):
                return mock_pom_tree
            if path == os.path.join(project_path, SRC_MAIN_MULE_PATH_NAME, "my-mule-project.xml"):
                return mock_mule_config_tree
            raise FileNotFoundError(f"Attempted to parse unexpected file: {path}")
        mock_et_parse.side_effect = et_parse_side_effect

        # Mock os.walk for target directory
        # Expected artifact: my-api-spec-1.0.0-raml.zip
        expected_zip_name = "my-api-spec-1.0.0-raml.zip"
        target_path = os.path.join(project_path, "target")
        mock_os_walk.return_value = [
            (target_path, [], [expected_zip_name, "other.jar"])
        ]

        results = api_validator.validate_api_spec_and_flows(project_path)

        self.assertEqual(results['api_spec_dependency'], "com.example:my-api-spec:1.0.0:raml:zip")
        self.assertTrue(results['api_spec_zip_found'])
        self.assertEqual(results['apikit_router_file'], "my-mule-project.xml")
        self.assertTrue(results['apikit_router_found'])
        self.assertEqual(len(results['notes']), 0)
        mock_os_walk.assert_called_once_with(target_path)


    @patch('os.path.isfile')
    @patch('xml.etree.ElementTree.parse')
    @patch('os.walk')
    @patch('os.path.basename')
    @patch('os.path.abspath')
    def test_raml_dependency_missing(self, mock_abspath, mock_basename, mock_os_walk, mock_et_parse, mock_isfile):
        project_path = "/dummy/project/no-raml-dep"
        mock_abspath.return_value = project_path
        mock_basename.return_value = "no-raml-dep"

        mock_isfile.return_value = True # Assume all files exist for simplicity here

        mock_pom_tree = MagicMock()
        mock_pom_tree.getroot.return_value = self._create_mock_pom_xml_tree(has_raml_dependency=False)
        mock_et_parse.return_value = mock_pom_tree # Simplified: only pom is parsed for this test focus

        results = api_validator.validate_api_spec_and_flows(project_path)

        self.assertIsNone(results['api_spec_dependency'])
        self.assertFalse(results['api_spec_zip_found'])
        self.assertIn("No API spec dependency with classifier 'raml' and type 'zip' found in pom.xml.", results['notes'])
        mock_os_walk.assert_not_called() # Should not walk target if spec name not derived

    @patch('os.path.isfile')
    @patch('xml.etree.ElementTree.parse')
    @patch('os.walk')
    @patch('os.path.basename')
    @patch('os.path.abspath')
    def test_raml_zip_not_in_target(self, mock_abspath, mock_basename, mock_os_walk, mock_et_parse, mock_isfile):
        project_path = "/dummy/project/zip-missing"
        mock_abspath.return_value = project_path
        mock_basename.return_value = "zip-missing"

        mock_isfile.return_value = True # pom.xml and mule config exist

        mock_pom_tree = MagicMock()
        mock_pom_tree.getroot.return_value = self._create_mock_pom_xml_tree() # Has RAML dep
        mock_et_parse.return_value = mock_pom_tree # Focus on POM and target

        target_path = os.path.join(project_path, "target")
        mock_os_walk.return_value = [ (target_path, [], ["other.jar"]) ] # ZIP is missing

        results = api_validator.validate_api_spec_and_flows(project_path)

        self.assertIsNotNone(results['api_spec_dependency'])
        self.assertFalse(results['api_spec_zip_found'])
        self.assertIn("API spec zip 'my-api-spec-1.0.0-raml.zip' not found in target/", results['notes'][0])

    @patch('os.path.isfile')
    @patch('xml.etree.ElementTree.parse') # Keep this to avoid UnboundLocalError if it were called
    @patch('os.walk')
    @patch('os.path.basename')
    @patch('os.path.abspath')
    def test_pom_xml_missing(self, mock_abspath, mock_basename, mock_os_walk, mock_et_parse, mock_isfile):
        project_path = "/dummy/project/no-pom"
        mock_abspath.return_value = project_path
        mock_basename.return_value = "no-pom"

        # Simulate only pom.xml is missing
        def isfile_side_effect(path):
            if path == os.path.join(project_path, "pom.xml"):
                return False
            return True # Other files like mule config might exist
        mock_isfile.side_effect = isfile_side_effect

        results = api_validator.validate_api_spec_and_flows(project_path)

        self.assertIsNone(results['api_spec_dependency'])
        self.assertFalse(results['api_spec_zip_found'])
        self.assertIn("No API spec dependency with classifier 'raml' and type 'zip' found in pom.xml.", results['notes'])
        mock_et_parse.assert_not_called() # ET.parse should not be called if pom.xml is missing
        mock_os_walk.assert_not_called() # os.walk for target should not be called

    @patch('os.path.isfile')
    @patch('xml.etree.ElementTree.parse')
    @patch('os.path.basename')
    @patch('os.path.abspath')
    @patch('mule_validator.api_validator.logger') # Mock logger
    def test_pom_parsing_error(self, mock_logger, mock_abspath, mock_basename, mock_et_parse, mock_isfile):
        project_path = "/dummy/project/bad-pom"
        mock_abspath.return_value = project_path
        mock_basename.return_value = "bad-pom"
        mock_isfile.return_value = True # pom.xml exists

        mock_et_parse.side_effect = ET.ParseError("mocked POM parse error")

        results = api_validator.validate_api_spec_and_flows(project_path)

        self.assertIsNone(results['api_spec_dependency'])
        self.assertFalse(results['api_spec_zip_found'])
        # Check if logger.error was called (specific message depends on implementation)
        mock_logger.error.assert_called_with(f"Error parsing pom.xml for API spec dependency: mocked POM parse error")
        # The note about missing dependency is still added because api_spec_dep remains None
        self.assertIn("No API spec dependency with classifier 'raml' and type 'zip' found in pom.xml.", results['notes'])

    @patch('os.path.isfile')
    @patch('xml.etree.ElementTree.parse')
    @patch('os.walk') # Mock os_walk as it's called for target
    @patch('os.path.basename')
    @patch('os.path.abspath')
    def test_mule_config_file_missing(self, mock_abspath, mock_basename, mock_os_walk, mock_et_parse, mock_isfile):
        project_path = "/dummy/project/no-mule-config"
        mock_abspath.return_value = project_path
        mock_basename.return_value = "no-mule-config"

        # pom.xml exists and is valid, RAML zip found
        mock_pom_tree = MagicMock()
        mock_pom_tree.getroot.return_value = self._create_mock_pom_xml_tree()

        # Simulate packagename.xml is missing, pom.xml exists
        def isfile_side_effect(path):
            if path == os.path.join(project_path, "pom.xml"):
                return True
            if path == os.path.join(project_path, SRC_MAIN_MULE_PATH_NAME, "no-mule-config.xml"):
                return False # Mule config is missing
            return False
        mock_isfile.side_effect = isfile_side_effect

        def et_parse_side_effect(path):
            if path == os.path.join(project_path, "pom.xml"):
                return mock_pom_tree
            # Should not be called for mule config if isfile is false
            raise FileNotFoundError(f"Attempted to parse non-existent file: {path}")
        mock_et_parse.side_effect = et_parse_side_effect

        mock_os_walk.return_value = [(os.path.join(project_path, "target"), [], ["my-api-spec-1.0.0-raml.zip"])]


        results = api_validator.validate_api_spec_and_flows(project_path)

        self.assertTrue(results['api_spec_zip_found']) # Prereqs met
        self.assertIsNone(results['apikit_router_file']) # Filename might be derived but not found
        self.assertFalse(results['apikit_router_found'])
        self.assertIn("Expected APIkit router/config file 'no-mule-config.xml' not found", results['notes'][0])
        self.assertIn("No APIkit router/config found in 'no-mule-config.xml'", results['notes'][1])


    @patch('os.path.isfile')
    @patch('xml.etree.ElementTree.parse')
    @patch('os.walk')
    @patch('os.path.basename')
    @patch('os.path.abspath')
    def test_no_apikit_router_in_mule_config(self, mock_abspath, mock_basename, mock_os_walk, mock_et_parse, mock_isfile):
        project_path = "/dummy/project/no-apikit"
        mock_abspath.return_value = project_path
        mock_basename.return_value = "no-apikit"

        mock_isfile.return_value = True # All relevant files exist

        mock_pom_tree = MagicMock()
        mock_pom_tree.getroot.return_value = self._create_mock_pom_xml_tree()

        mock_mule_config_tree = MagicMock()
        mock_mule_config_tree.getroot.return_value = self._create_mock_mule_config_xml_tree(has_apikit_router=False)

        def et_parse_side_effect(path):
            if path == os.path.join(project_path, "pom.xml"): return mock_pom_tree
            if path == os.path.join(project_path, SRC_MAIN_MULE_PATH_NAME, "no-apikit.xml"): return mock_mule_config_tree
            raise FileNotFoundError(f"Attempted to parse unexpected file: {path}")
        mock_et_parse.side_effect = et_parse_side_effect
        mock_os_walk.return_value = [(os.path.join(project_path, "target"), [], ["my-api-spec-1.0.0-raml.zip"])]

        results = api_validator.validate_api_spec_and_flows(project_path)

        self.assertTrue(results['api_spec_zip_found'])
        self.assertEqual(results['apikit_router_file'], None) # File was parsed, but no router found, so this stays None
        self.assertFalse(results['apikit_router_found'])
        self.assertIn("No APIkit router/config found in 'no-apikit.xml'", results['notes'][0])

    @patch('os.path.isfile')
    @patch('xml.etree.ElementTree.parse')
    @patch('os.walk')
    @patch('os.path.basename')
    @patch('os.path.abspath')
    @patch('mule_validator.api_validator.logger')
    def test_mule_config_parsing_error(self, mock_logger, mock_abspath, mock_basename, mock_os_walk, mock_et_parse, mock_isfile):
        project_path = "/dummy/project/bad-mule-config"
        mock_abspath.return_value = project_path
        mock_basename.return_value = "bad-mule-config"
        mock_isfile.return_value = True # All files exist

        mock_pom_tree = MagicMock()
        mock_pom_tree.getroot.return_value = self._create_mock_pom_xml_tree()

        def et_parse_side_effect(path):
            if path == os.path.join(project_path, "pom.xml"): return mock_pom_tree
            if path == os.path.join(project_path, SRC_MAIN_MULE_PATH_NAME, "bad-mule-config.xml"):
                raise ET.ParseError("mocked mule config parse error")
            raise FileNotFoundError(f"Attempted to parse unexpected file: {path}")
        mock_et_parse.side_effect = et_parse_side_effect
        mock_os_walk.return_value = [(os.path.join(project_path, "target"), [], ["my-api-spec-1.0.0-raml.zip"])]

        results = api_validator.validate_api_spec_and_flows(project_path)

        self.assertTrue(results['api_spec_zip_found'])
        self.assertIsNone(results['apikit_router_file'])
        self.assertFalse(results['apikit_router_found'])
        mock_logger.error.assert_called_with(f"Error parsing XML file: {os.path.join(project_path, SRC_MAIN_MULE_PATH_NAME, 'bad-mule-config.xml')} - mocked mule config parse error")
        # Note for missing router is still added
        self.assertIn("No APIkit router/config found in 'bad-mule-config.xml'", results['notes'][0])

    @patch('os.path.isfile')
    @patch('xml.etree.ElementTree.parse')
    @patch('os.walk')
    @patch('os.path.basename')
    @patch('os.path.abspath')
    def test_apikit_router_alternative_namespace(self, mock_abspath, mock_basename, mock_os_walk, mock_et_parse, mock_isfile):
        project_path = "/dummy/project/alt-ns-apikit"
        mock_abspath.return_value = project_path
        mock_basename.return_value = "alt-ns-apikit"
        mock_isfile.return_value = True

        mock_pom_tree = MagicMock()
        mock_pom_tree.getroot.return_value = self._create_mock_pom_xml_tree()

        # Use the second namespace for APIkit
        mock_mule_config_tree = MagicMock()
        mock_mule_config_tree.getroot.return_value = self._create_mock_mule_config_xml_tree(has_apikit_router=True, apikit_ns_index=1)

        def et_parse_side_effect(path):
            if path == os.path.join(project_path, "pom.xml"): return mock_pom_tree
            if path == os.path.join(project_path, SRC_MAIN_MULE_PATH_NAME, "alt-ns-apikit.xml"): return mock_mule_config_tree
            raise FileNotFoundError(f"Attempted to parse unexpected file: {path}")
        mock_et_parse.side_effect = et_parse_side_effect
        mock_os_walk.return_value = [(os.path.join(project_path, "target"), [], ["my-api-spec-1.0.0-raml.zip"])]

        results = api_validator.validate_api_spec_and_flows(project_path)

        self.assertTrue(results['api_spec_zip_found'])
        self.assertEqual(results['apikit_router_file'], "alt-ns-apikit.xml")
        self.assertTrue(results['apikit_router_found'])
        self.assertEqual(len(results['notes']), 0)

if __name__ == '__main__':
    unittest.main()
