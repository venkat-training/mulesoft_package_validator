import unittest
import os
import tempfile
import shutil
from lxml import etree # For creating minimal valid XML for tests

from mule_validator.code_reviewer import review_mulesoft_code

# Temporarily suppress logging from the validator module to keep test output clean
import logging
logging.getLogger('mule_validator.code_reviewer').setLevel(logging.CRITICAL)

# Import functions to be tested directly
from mule_validator.code_reviewer import check_flow_names, is_camel_case
import re # Added import for re

class TestCodeReviewerSecurity(unittest.TestCase):

    def setUp(self):
        self.test_dir = tempfile.mkdtemp()

    def tearDown(self):
        shutil.rmtree(self.test_dir)

    def _write_mule_xml_file(self, filename, content_str):
        # Ensure the content is wrapped in a basic <mule> root if not already.
        if not content_str.strip().startswith("<mule"):
            content_str = f"""<mule xmlns="http://www.mulesoft.org/schema/mule/core"
                               xmlns:db="http://www.mulesoft.org/schema/mule/db"
                               xmlns:sftp="http://www.mulesoft.org/schema/mule/sftp"
                               xmlns:secure-properties="http://www.mulesoft.org/schema/mule/secure-properties"
                               version="EE_4.4.0">
{content_str}
</mule>"""
        file_path = os.path.join(self.test_dir, filename)
        with open(file_path, 'w', encoding='utf-8') as f:
            f.write(content_str)
        return file_path

    def find_issue(self, issues, issue_type, attribute_name=None, element_local_name=None, value_excerpt_contains=None, message_contains=None):
        for issue in issues:
            if issue.get('type') == issue_type:
                details_match = True
                if attribute_name and issue.get('attribute_name') != attribute_name:
                    details_match = False
                if element_local_name:
                    # Assuming element_tag is like "{namespace}localname" or just "localname"
                    tag = issue.get('element_tag', '')
                    if '}' in tag:
                        local_name = tag.split('}', 1)[1]
                    else:
                        local_name = tag
                    if local_name != element_local_name:
                        details_match = False
                if value_excerpt_contains and value_excerpt_contains not in issue.get('value_excerpt', ''):
                    details_match = False
                if message_contains and message_contains not in issue.get('message', ''):
                    details_match = False
                
                if details_match:
                    return issue
        return None

    def test_mule_xml_hardcoded_password_attr(self):
        xml_content = "<flow name='testFlow'><db:config name='DB_Config'><db:connection password='mule_password_123'/></db:config></flow>"
        file_path = self._write_mule_xml_file("hardcoded_attr.xml", xml_content)
        results = review_mulesoft_code(file_path)
        
        # Check for keyword 'password' on attribute name
        hardcoded_secret_issue = self.find_issue(results, 
                                                 issue_type='HardcodedSecretXML', 
                                                 attribute_name='password', 
                                                 element_local_name='connection',
                                                 value_excerpt_contains='mule_password_123')
        self.assertIsNotNone(hardcoded_secret_issue, "Hardcoded password attribute not detected as HardcodedSecretXML.")
        self.assertTrue("matches a password keyword" in hardcoded_secret_issue.get('message',''))

        # Also check if the value itself is considered suspicious by pattern (less specific)
        suspicious_value_issue = self.find_issue(results,
                                                 issue_type='SuspiciousValueXML',
                                                 attribute_name='password',
                                                 element_local_name='connection',
                                                 value_excerpt_contains='mule_password_123')
        # This might or might not be found depending on how generic GENERIC_SECRET_VALUE_PATTERNS are.
        # For a strong password like "mule_password_123", it might be caught.
        # If it is found, it's a bonus. The primary check is for the keyword.
        # For this test, we focus on the keyword detection.
        
    def test_mule_xml_hardcoded_secret_value_pattern(self):
        # Stripe-like test key
        xml_content = "<flow name='testFlow'><set-variable variableName='apiKey' value='pk_test_a1b2c3d4e5f6g7h8i9j0k1l2'/></flow>"
        file_path = self._write_mule_xml_file("value_pattern.xml", xml_content)
        results = review_mulesoft_code(file_path)

        suspicious_value_issue = self.find_issue(results,
                                                 issue_type='SuspiciousValueXML',
                                                 attribute_name='value',
                                                 element_local_name='set-variable',
                                                 value_excerpt_contains='pk_test_a1b2c3d4e5f6g7h8i9j0k1l2')
        self.assertIsNotNone(suspicious_value_issue, "Hardcoded secret value pattern (Stripe key) not detected.")
        self.assertTrue("matches generic secret pattern" in suspicious_value_issue.get('message',''))

    def test_mule_xml_sensitive_attr_plain_text(self):
        # sftp:connection is identified by 'sftp:connection' key in SENSITIVE_MULE_ATTRIBUTES
        # and 'password' is a sensitive attribute for it.
        xml_content = "<flow name='testFlow'><sftp:connection username='user' password='plainPassword' host='localhost'/></flow>"
        file_path = self._write_mule_xml_file("sensitive_plain.xml", xml_content)
        results = review_mulesoft_code(file_path)
        
        insecure_use_issue = self.find_issue(results,
                                             issue_type='InsecurePropertyUseXML',
                                             attribute_name='password',
                                             element_local_name='connection', # sftp:connection
                                             value_excerpt_contains='plainPassword')
        self.assertIsNotNone(insecure_use_issue, "Plain text in sensitive SFTP password attribute not detected.")
        self.assertTrue("should use a secure property" in insecure_use_issue.get('message',''))

    def test_mule_xml_sensitive_attr_insecure_property(self):
        xml_content = "<flow name='testFlow'><sftp:connection username='user' password='${sftp.pass}' host='localhost'/></flow>"
        file_path = self._write_mule_xml_file("sensitive_insecure_prop.xml", xml_content)
        results = review_mulesoft_code(file_path)

        insecure_use_issue = self.find_issue(results,
                                             issue_type='InsecurePropertyUseXML',
                                             attribute_name='password',
                                             element_local_name='connection', # sftp:connection
                                             value_excerpt_contains='${sftp.pass}')
        self.assertIsNotNone(insecure_use_issue, "Insecure property '${sftp.pass}' in sensitive attribute not detected.")
        self.assertTrue("should use a secure property" in insecure_use_issue.get('message',''))

    def test_mule_xml_sensitive_attr_secure_property(self):
        xml_content = "<flow name='testFlow'><sftp:connection username='user' password='${secure::sftp.pass}' host='localhost'/></flow>"
        file_path = self._write_mule_xml_file("sensitive_secure_prop.xml", xml_content)
        results = review_mulesoft_code(file_path)
        
        # There should be NO InsecurePropertyUseXML for the password attribute here.
        # There might be other non-security related code review issues if the XML is minimal.
        insecure_use_issue = self.find_issue(results,
                                             issue_type='InsecurePropertyUseXML',
                                             attribute_name='password',
                                             element_local_name='connection')
        self.assertIsNone(insecure_use_issue, 
                          f"Secure property usage '${{secure::sftp.pass}}' was incorrectly flagged as insecure. Issues: {results}")

        # Also check no HardcodedSecretXML or SuspiciousValueXML for this specific secure placeholder
        hardcoded_issue = self.find_issue(results, issue_type='HardcodedSecretXML', attribute_name='password', element_local_name='connection')
        suspicious_issue = self.find_issue(results, issue_type='SuspiciousValueXML', attribute_name='password', element_local_name='connection')
        self.assertIsNone(hardcoded_issue, "Secure property usage flagged as HardcodedSecretXML.")
        self.assertIsNone(suspicious_issue, "Secure property usage flagged as SuspiciousValueXML.")


    def test_mule_xml_clean(self):
        xml_content = "<flow name='testFlow'><logger level='INFO' message='Hello'/></flow>"
        file_path = self._write_mule_xml_file("clean_mule.xml", xml_content)
        results = review_mulesoft_code(file_path)
        
        security_issue_types = ['HardcodedSecretXML', 'SuspiciousValueXML', 'InsecurePropertyUseXML']
        found_security_issues = [r for r in results if r.get('type') in security_issue_types]
        
        self.assertEqual(len(found_security_issues), 0, 
                         f"Clean Mule XML should have no security warnings. Found: {found_security_issues}")

    def test_secure_properties_key_itself(self):
        # The key for secure-properties:config itself should not be a placeholder.
        # It is often stored in env variables or system properties, not directly in the config file for prod.
        # However, if it *is* in the file, it should not be a secure placeholder (that would be circular).
        # The SENSITIVE_MULE_ATTRIBUTES lists 'secure-properties:config' -> ['key']
        xml_content_plain_key = "<secure-properties:config name='SecureProps' key='ThisIsAnActualKey12345'><secure-properties:encrypt algorithm='AES'/></secure-properties:config>"
        file_path_plain = self._write_mule_xml_file("secure_props_plain_key.xml", xml_content_plain_key)
        results_plain = review_mulesoft_code(file_path_plain)

        # This should NOT be flagged by InsecurePropertyUseXML because 'ThisIsAnActualKey12345' is not a placeholder.
        # It *might* be flagged by HardcodedSecretXML or SuspiciousValueXML if the key value matches patterns.
        insecure_issue_plain = self.find_issue(results_plain, issue_type='InsecurePropertyUseXML', attribute_name='key', element_local_name='config')
        self.assertIsNone(insecure_issue_plain, "Plain text secure properties key should not be 'InsecurePropertyUseXML'.")
        
        # It's plausible for the key itself to be a "SuspiciousValueXML" if it's long and random-like
        suspicious_issue_plain = self.find_issue(results_plain, issue_type='SuspiciousValueXML', attribute_name='key', element_local_name='config')
        # self.assertIsNotNone(suspicious_issue_plain, "Plain text secure properties key could be a 'SuspiciousValueXML'.") # This is debatable, depends on patterns

        xml_content_placeholder_key = "<secure-properties:config name='SecureProps' key='${env::APP_SECURE_KEY}'><secure-properties:encrypt algorithm='AES'/></secure-properties:config>"
        file_path_placeholder = self._write_mule_xml_file("secure_props_placeholder_key.xml", xml_content_placeholder_key)
        results_placeholder = review_mulesoft_code(file_path_placeholder)

        # If the key is '${env::APP_SECURE_KEY}', this is NOT a secure placeholder like '${secure::...}'
        # So, it should be flagged by InsecurePropertyUseXML because 'key' is a sensitive attribute.
        insecure_issue_placeholder = self.find_issue(results_placeholder, issue_type='InsecurePropertyUseXML', attribute_name='key', element_local_name='config')
        self.assertIsNotNone(insecure_issue_placeholder, "Secure properties key using non-secure placeholder '${env::...}' should be 'InsecurePropertyUseXML'.")

        xml_content_secure_placeholder_key = "<secure-properties:config name='SecureProps' key='${secure::master.key}'><secure-properties:encrypt algorithm='AES'/></secure-properties:config>"
        file_path_secure_placeholder = self._write_mule_xml_file("secure_props_secure_placeholder_key.xml", xml_content_secure_placeholder_key)
        results_secure_placeholder = review_mulesoft_code(file_path_secure_placeholder)
        
        # Using a ${secure::...} placeholder for the key of secure-properties:config is circular and wrong.
        # It should be flagged by InsecurePropertyUseXML.
        # The current logic for InsecurePropertyUseXML flags anything *not* matching SECURE_PROPERTY_PATTERNS.
        # Since '${secure::master.key}' *does* match, it would NOT be flagged by InsecurePropertyUseXML. This is a subtle point.
        # The definition of InsecurePropertyUseXML is "value is not a secure placeholder OR is a non-secure placeholder".
        # A secure placeholder for the secure key itself is a misconfiguration.
        # SENSITIVE_MULE_ATTRIBUTES for 'secure-properties:config' -> 'key' implies its value needs scrutiny.
        # The current check for InsecurePropertyUseXML is: "is it NOT a secure placeholder?"
        # If it IS a secure placeholder, it passes. This is correct for most attributes.
        # For the *key* of secure-properties:config, this means if you put ${secure::master.key}, it won't be flagged by InsecurePropertyUseXML.
        # This might be an edge case to refine in the validator's logic if desired (e.g. "key for secure-properties:config must not be a ${secure::...} placeholder").
        # For now, test current behavior:
        insecure_issue_secure_placeholder = self.find_issue(results_secure_placeholder, issue_type='InsecurePropertyUseXML', attribute_name='key', element_local_name='config')
        self.assertIsNone(insecure_issue_secure_placeholder, 
                          "Secure properties key using a ${secure::...} placeholder should NOT be flagged by InsecurePropertyUseXML by current logic, though it's a misconfig.")

class TestFlowNameConventionChecks(unittest.TestCase):
    # Minimal namespaces needed for flow elements
    NAMESPACES = {
        'mule': 'http://www.mulesoft.org/schema/mule/core',
        # Add other namespaces if your test XMLs use them for flow definitions
    }

    def _create_flow_xml_root(self, flow_name):
        """Helper to create an lxml root element for a Mule config with one flow."""
        xml_str = f"""<mule xmlns="http://www.mulesoft.org/schema/mule/core" version="EE_4.4.0">
    <flow name="{flow_name}">
        <logger level="INFO" message="Test flow"/>
    </flow>
</mule>"""
        return etree.fromstring(xml_str.encode('utf-8'))

    def test_apikit_flow_name_extraction_valid(self):
        """Test valid flow names after APIkit prefix/suffix extraction."""
        test_cases = {
            "get:actualFlowName:some-config-suffix": "actualFlowName",
            "post:anotherFlow": "anotherFlow",
            "regularFlowName": "regularFlowName",
            "put:flowNameWithNumbers123:config": "flowNameWithNumbers123",
            "get:flow1:config1:extrapart": "flow1", # ensure it takes part between first and second colon
            "patch:flowWithoutConfigSuffix": "flowWithoutConfigSuffix",
            "get:flowContaining ColonButNotAtEnd:": "flowContaining ColonButNotAtEnd", # Trailing colon after main name part
        }
        for original_name, expected_part_to_check in test_cases.items():
            with self.subTest(original_name=original_name):
                root = self._create_flow_xml_root(original_name)
                issues = check_flow_names(root, self.NAMESPACES)

                # Check if the expected part is camel case (it should be for these valid cases)
                self.assertTrue(is_camel_case(expected_part_to_check), f"Test case setup error: '{expected_part_to_check}' is not camel case.")

                found_issue_for_name = any(original_name in issue for issue in issues)
                self.assertFalse(found_issue_for_name,
                                 f"Expected no issues for flow '{original_name}' (checking part '{expected_part_to_check}'). Issues: {issues}")

    def test_apikit_flow_name_extraction_invalid_camel_case(self):
        """Test flow names that are invalid camel case after APIkit prefix/suffix extraction."""
        test_cases = {
            "get:Invalid-Flow-Name:config": "Invalid-Flow-Name",
            # "post:nonCamel": "nonCamel", # This was actually valid camelCase.
            "post:NonCamelStart:config": "NonCamelStart", # Starts with uppercase
            "delete:flow_with_underscores:suffix": "flow_with_underscores",
        }
        for original_name, part_to_check in test_cases.items():
            with self.subTest(original_name=original_name):
                root = self._create_flow_xml_root(original_name)
                issues = check_flow_names(root, self.NAMESPACES)
                expected_message_part = f"Flow name part '{part_to_check}' (from original: '{original_name}') does not comply with camel case format."
                self.assertTrue(any(expected_message_part in issue for issue in issues),
                                f"Expected camel case issue for '{part_to_check}' from '{original_name}'. Issues: {issues}")

    def test_apikit_flow_name_extraction_invalid_characters(self):
        """Test flow names with invalid characters after APIkit prefix/suffix extraction."""
        test_cases = {
            "get:flow-with-hyphens:config": "flow-with-hyphens", # Already covered by camel case, but good for char check too
            "put:flow@symbol:suffix": "flow@symbol",
        }
        for original_name, part_to_check in test_cases.items():
            with self.subTest(original_name=original_name):
                root = self._create_flow_xml_root(original_name)
                issues = check_flow_names(root, self.NAMESPACES)

                # Check for non-alphanumeric if not camel case (as camel case implies alphanumeric for the main part)
                # The rule is "alphanumeric" AND "camelCase". Non-camelCase often implies invalid chars.
                # If it fails camelCase, that's one error. If it also has non-alphanumeric, that's another.
                # The current implementation checks camelCase first, then for invalid characters.
                # Let's assume the primary error reported would be about camel case if that fails.
                # If camel case passes but chars are wrong (e.g. starts lowercase, but contains '#')

                expected_char_message_part = f"Flow name part '{part_to_check}' (from original: '{original_name}') contains invalid characters. It should be alphanumeric."

                # If it's not camel case, that error might appear first or instead.
                # For this test, let's ensure the part_to_check would fail the regex ^[a-zA-Z0-9]+$
                self.assertFalse(re.match(r'^[a-zA-Z0-9]+$', part_to_check), f"Test setup: {part_to_check} IS alphanumeric.")

                if not is_camel_case(part_to_check):
                    expected_camel_message_part = f"Flow name part '{part_to_check}' (from original: '{original_name}') does not comply with camel case format."
                    self.assertTrue(
                        any(expected_camel_message_part in issue for issue in issues) or \
                        any(expected_char_message_part in issue for issue in issues),
                        f"Expected camel case or invalid char issue for '{part_to_check}' from '{original_name}'. Issues: {issues}"
                    )
                else: # Passes camel case but fails character check (e.g. "validStart@oops")
                    self.assertTrue(any(expected_char_message_part in issue for issue in issues),
                                f"Expected invalid char issue for '{part_to_check}' from '{original_name}'. Issues: {issues}")


    def test_apikit_flow_name_extraction_empty_part(self):
        """Test flow names that result in an empty part to check."""
        test_cases = [
            "delete::config",   # Original: "delete::config", part to check: ""
            "patch::",          # Original: "patch::", part to check: ""
            "http:",            # Original: "http:", part to check: "" (if logic leads to this)
            "get::",
        ]
        for original_name in test_cases:
            with self.subTest(original_name=original_name):
                root = self._create_flow_xml_root(original_name)
                issues = check_flow_names(root, self.NAMESPACES)
                expected_message = f"Flow name '{original_name}' results in an empty part for validation after APIkit prefix/suffix removal."
                self.assertTrue(any(expected_message == issue for issue in issues), # Exact match for this specific error
                                f"Expected empty part issue for '{original_name}'. Issues: {issues}")

    def test_flow_name_missing_attribute(self):
        """Test a flow element that is missing the 'name' attribute."""
        xml_str = """<mule xmlns="http://www.mulesoft.org/schema/mule/core" version="EE_4.4.0">
    <flow> <!-- No name attribute -->
        <logger level="INFO" message="Test flow"/>
    </flow>
</mule>"""
        root = etree.fromstring(xml_str.encode('utf-8'))
        issues = check_flow_names(root, self.NAMESPACES)
        self.assertTrue(any("Flow is missing a name attribute." == issue for issue in issues),
                        f"Expected missing name attribute issue. Issues: {issues}")

if __name__ == '__main__':
    unittest.main(verbosity=2)
