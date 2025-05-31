import unittest
import os
import tempfile
import shutil
# from xml.etree.ElementTree import ParseError # Not needed as ET is internal to validator

from mule_validator.dependency_validator import validate_dependencies_and_size

# Temporarily suppress logging from the validator module to keep test output clean
import logging
logging.getLogger('mule_validator.dependency_validator').setLevel(logging.CRITICAL)

class TestDependencyValidatorSecurity(unittest.TestCase):

    def setUp(self):
        self.test_dir = tempfile.mkdtemp()
        self.package_folder_path = self.test_dir
        # Create a dummy build folder path; its content doesn't matter for these tests
        self.build_folder_path = os.path.join(self.test_dir, "build_target")
        os.makedirs(self.build_folder_path, exist_ok=True)

    def tearDown(self):
        shutil.rmtree(self.test_dir)

    def _write_pom_xml(self, content_str):
        pom_path = os.path.join(self.package_folder_path, "pom.xml")
        with open(pom_path, 'w', encoding='utf-8') as f:
            f.write(content_str)
        return pom_path

    def test_pom_with_secret_property(self):
        # Basic project structure for valid POM, even if not fully compliant for a real build
        pom_content = """
<project xmlns="http://maven.apache.org/POM/4.0.0"
         xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance"
         xsi:schemaLocation="http://maven.apache.org/POM/4.0.0 http://maven.apache.org/xsd/maven-4.0.0.xsd">
    <modelVersion>4.0.0</modelVersion>
    <groupId>com.example</groupId>
    <artifactId>test-app-secret-prop</artifactId>
    <version>1.0.0</version>
    <packaging>jar</packaging>
    <properties>
        <my.secret.password>pom_secret_value_in_property</my.secret.password>
        <another.property>safe_value</another.property>
    </properties>
</project>
"""
        self._write_pom_xml(pom_content)
        results = validate_dependencies_and_size(self.package_folder_path, self.build_folder_path)
        
        warnings = results.get('pom_security_warnings', [])
        self.assertGreater(len(warnings), 0, "Should find at least one security warning for property.")
        
        # Check for keyword match on the property tag name
        # The tag 'my.secret.password' contains 'password' (a keyword)
        found_keyword_on_tag = any(
            w.get('xml_path') == 'my.secret.password' and # Simplified path is the tag name
            (w.get('issue_type') == 'Hardcoded Secret') and
            ("matches a password keyword" in w.get('message', '') or "matches a generic secret keyword" in w.get('message', '')) and
            "pom_secret_value_in_property" in w.get('value_excerpt', '')
            for w in warnings
        )
        self.assertTrue(found_keyword_on_tag, "Secret in property name (tag keyword) not detected correctly.")

    def test_pom_with_secret_in_plugin_config_text(self):
        pom_content = """
<project xmlns="http://maven.apache.org/POM/4.0.0">
    <modelVersion>4.0.0</modelVersion>
    <groupId>com.example</groupId>
    <artifactId>test-app-plugin-text</artifactId>
    <version>1.0.0</version>
    <packaging>jar</packaging>
    <build><plugins><plugin>
        <groupId>org.example</groupId><artifactId>my-plugin</artifactId>
        <configuration>
            <secretToken>plugin_token_secret_value_shhh</secretToken>
            <anotherConfig>safe</anotherConfig>
        </configuration>
    </plugin></plugins></build>
</project>
"""
        self._write_pom_xml(pom_content)
        results = validate_dependencies_and_size(self.package_folder_path, self.build_folder_path)
        warnings = results.get('pom_security_warnings', [])
        self.assertGreater(len(warnings), 0, "Should find security warning for plugin config text.")

        # Check for keyword match on the <secretToken> tag
        secret_token_tag_warning = any(
            w.get('xml_path') == 'secretToken' and # Simplified path is the tag name
            w.get('issue_type') == 'Hardcoded Secret' and # 'secretToken' tag contains 'secret' and 'token' keywords
            "plugin_token_secret_value_shhh" in w.get('value_excerpt', '')
            for w in warnings
        )
        self.assertTrue(secret_token_tag_warning, "Secret in plugin config text (tag keyword 'secretToken') not detected.")

    def test_pom_with_secret_in_plugin_config_attribute(self):
        pom_content = """
<project xmlns="http://maven.apache.org/POM/4.0.0">
    <modelVersion>4.0.0</modelVersion>
    <groupId>com.example</groupId>
    <artifactId>test-app-plugin-attr</artifactId>
    <version>1.0.0</version>
    <packaging>jar</packaging>
    <build><plugins><plugin>
        <groupId>org.example</groupId><artifactId>my-plugin</artifactId>
        <configuration>
            <myPluginConfig password='attr_secret_for_plugin_config'/>
        </configuration>
    </plugin></plugins></build>
</project>
"""
        self._write_pom_xml(pom_content)
        results = validate_dependencies_and_size(self.package_folder_path, self.build_folder_path)
        warnings = results.get('pom_security_warnings', [])
        self.assertGreater(len(warnings), 0, "Should find security warning for plugin config attribute.")

        # Check for keyword match on the 'password' attribute name
        attr_keyword_warning = any(
            w.get('xml_path') == 'myPluginConfig' and # Simplified path is the tag name
            w.get('attribute_name') == 'password' and
            w.get('issue_type') == 'Hardcoded Secret' and # 'password' attribute name is a keyword
            "attr_secret_for_plugin_config" in w.get('value_excerpt', '')
            for w in warnings
        )
        self.assertTrue(attr_keyword_warning, "Secret in plugin config attribute (name 'password') not detected.")


    def test_pom_clean_no_secrets(self):
        pom_content = """
<project xmlns="http://maven.apache.org/POM/4.0.0">
    <modelVersion>4.0.0</modelVersion>
    <groupId>com.example</groupId>
    <artifactId>clean-app</artifactId>
    <version>1.0.0</version>
    <packaging>jar</packaging>
    <dependencies>
        <dependency><groupId>junit</groupId><artifactId>junit</artifactId><version>4.12</version></dependency>
    </dependencies>
</project>
"""
        self._write_pom_xml(pom_content)
        results = validate_dependencies_and_size(self.package_folder_path, self.build_folder_path)
        warnings = results.get('pom_security_warnings', [])
        self.assertEqual(len(warnings), 0, f"Clean POM should have no security warnings. Got: {warnings}")
        self.assertIsNone(results.get('pom_parsing_error'), "Clean POM should not have parsing error.")

    def test_pom_file_not_found(self):
        # Intentionally do not write pom.xml
        with self.assertRaises(FileNotFoundError) as context:
            validate_dependencies_and_size(self.package_folder_path, self.build_folder_path)
        self.assertTrue("POM file not found" in str(context.exception))

    def test_pom_invalid_xml_syntax(self):
        pom_content = "<project><version>1.0.0</version><artifactId>my-app</artifactId></project>" # Missing closing </project> and other required elements
        self._write_pom_xml(pom_content)
        
        results = validate_dependencies_and_size(self.package_folder_path, self.build_folder_path)
        
        self.assertIsNotNone(results.get('pom_parsing_error'), "Should report a POM parsing error for invalid XML.")
        # The exact message might vary based on the parser, so check for key phrases.
        self.assertTrue("Could not parse" in results['pom_parsing_error'] and "Secret scanning skipped" in results['pom_parsing_error'])
        self.assertEqual(len(results.get('pom_security_warnings', [])), 0, 
                         "No security warnings should be present if POM parsing failed.")

if __name__ == '__main__':
    unittest.main(verbosity=2)
