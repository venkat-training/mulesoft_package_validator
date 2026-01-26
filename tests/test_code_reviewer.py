import unittest
from unittest.mock import patch, MagicMock, mock_open
import os
from lxml import etree # For creating minimal valid XML for tests
import sys

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

from mule_validator import code_reviewer

# Namespaces used in tests
NS_MAP = {
    'mule': 'http://www.mulesoft.org/schema/mule/core',
    'http': 'http://www.mulesoft.org/schema/mule/http',
    'dw': 'http://www.mulesoft.org/schema/mule/ee/dw',
    'secure-properties': 'http://www.mulesoft.org/schema/mule/secure-properties',
    'sftp': 'http://www.mulesoft.org/schema/mule/sftp',
    'db': 'http://www.mulesoft.org/schema/mule/db', # Added for completeness from original test file context
    'scheduler': 'http://www.mulesoft.org/schema/mule/scheduler',
    'concur': 'http://www.mulesoft.org/schema/mule/concur',
    'ftp': 'http://www.mulesoft.org/schema/mule/ftp',
    'smb': 'http://www.mulesoft.org/schema/mule/smb',
    'vm': 'http://www.mulesoft.org/schema/mule/vm',
    's3': 'http://www.mulesoft.org/schema/mule/s3',
    'smtp': 'http://www.mulesoft.org/schema/mule/smtp',
    # Ensure all prefixes used in check_*.findall are covered
}

class TestCodeReviewerIsCamelCase(unittest.TestCase):
    def test_is_camel_case_valid(self):
        self.assertTrue(code_reviewer.is_camel_case("validCamelCase"))
        self.assertTrue(code_reviewer.is_camel_case("anotherValidName123"))
        self.assertTrue(code_reviewer.is_camel_case("a")) # Single lowercase
        self.assertTrue(code_reviewer.is_camel_case("flow"))

    def test_is_camel_case_invalid(self):
        self.assertFalse(code_reviewer.is_camel_case("InvalidCamelCase")) # Starts with uppercase
        self.assertFalse(code_reviewer.is_camel_case("not_camel_case")) # Contains underscore
        self.assertFalse(code_reviewer.is_camel_case("not-camel-case")) # Contains hyphen
        self.assertFalse(code_reviewer.is_camel_case("ALLUPPER"))
        self.assertFalse(code_reviewer.is_camel_case("nameWith Space"))

    def test_is_camel_case_empty_and_none(self):
        # Current behavior of re.match will return False for empty string
        self.assertFalse(code_reviewer.is_camel_case(""))
        with self.assertRaises(TypeError): # name is str, None is not
             code_reviewer.is_camel_case(None)


class TestCodeReviewerCheckFunctions(unittest.TestCase):
    def _create_xml_root(self, xml_string_content):
        """
        Helper to create a root element from a string containing specific elements for a check.
        Ensure all namespaces possibly used by child xml_string_content are declared here.
        """
        xml_full = f"""<mule xmlns="http://www.mulesoft.org/schema/mule/core"
                        xmlns:apikit="http://www.mulesoft.org/schema/mule/mule-apikit"
                        xmlns:http="http://www.mulesoft.org/schema/mule/http"
                        xmlns:db="http://www.mulesoft.org/schema/mule/db"
                        xmlns:dw="http://www.mulesoft.org/schema/mule/ee/dw"
                        xmlns:sftp="http://www.mulesoft.org/schema/mule/sftp"
                        xmlns:ftp="http://www.mulesoft.org/schema/mule/ftp"
                        xmlns:smb="http://www.mulesoft.org/schema/mule/smb"
                        xmlns:vm="http://www.mulesoft.org/schema/mule/vm"
                        xmlns:s3="http://www.mulesoft.org/schema/mule/s3"
                        xmlns:smtp="http://www.mulesoft.org/schema/mule/smtp"
                        xmlns:concur="http://www.mulesoft.org/schema/mule/concur"
                        xmlns:scheduler="http://www.mulesoft.org/schema/mule/scheduler"
                        xmlns:secure-properties="http://www.mulesoft.org/schema/mule/secure-properties">
            {xml_string_content}
        </mule>"""
        return etree.fromstring(xml_full.encode('utf-8'))

    def test_check_flow_names_valid(self):
        root = self._create_xml_root('<flow name="get:validFlowName:config"/>')
        issues = code_reviewer.check_flow_names(root, NS_MAP)
        self.assertEqual(len(issues), 0)

    def test_check_flow_names_invalid(self):
        """Test invalid flow name patterns - using clearly invalid formats"""
        # Use snake_case which is definitely invalid according to is_camel_case
        root = self._create_xml_root('<flow name="get:invalid_flow_name:config"/>')
        issues = code_reviewer.check_flow_names(root, NS_MAP)
        self.assertGreater(len(issues), 0, 
            f"Expected camel case violation for 'invalid_flow_name', got: {issues}")
        self.assertTrue(
            any("invalid_flow_name" in issue and "camel case" in issue.lower() for issue in issues),
            f"Expected message about camel case for 'invalid_flow_name', got: {issues}"
        )

    def test_check_flow_names_missing_name(self):
        root = self._create_xml_root('<flow />')
        issues = code_reviewer.check_flow_names(root, NS_MAP)
        self.assertIn("Flow is missing a name attribute.", issues)

    def test_check_http_listener_valid(self):
        root = self._create_xml_root('<http:listener path="/api/*" config-ref="test"/>') # Assuming config-ref is needed for it to be 'valid' in a real scenario
        issues = code_reviewer.check_http_listener(root, NS_MAP)
        self.assertEqual(len(issues), 0)

    def test_check_http_listener_missing_path(self):
        root = self._create_xml_root('<http:listener config-ref="test"/>')
        issues = code_reviewer.check_http_listener(root, NS_MAP)
        self.assertIn("HTTP Listener is missing a path attribute.", issues)

    def test_check_logger_valid(self):
        root = self._create_xml_root('<logger message="Test log"/>')
        issues = code_reviewer.check_logger(root, NS_MAP)
        self.assertEqual(len(issues), 0)

    def test_check_logger_missing_message(self):
        root = self._create_xml_root('<logger />')
        issues = code_reviewer.check_logger(root, NS_MAP)
        self.assertIn("Logger is missing a message attribute.", issues)

    def test_check_dataweave_valid(self):
        root = self._create_xml_root('<dw:transform-message><dw:set-payload>payload</dw:set-payload></dw:transform-message>')
        issues = code_reviewer.check_dataweave(root, NS_MAP)
        self.assertEqual(len(issues), 0)

    def test_check_dataweave_missing_set_payload(self):
        root = self._create_xml_root('<dw:transform-message><dw:set-variable variableName="v">1</dw:set-variable></dw:transform-message>')
        issues = code_reviewer.check_dataweave(root, NS_MAP)
        self.assertIn("DataWeave transformation is missing a set-payload element.", issues)

    def test_contains_secure_properties_config_present(self):
        root = self._create_xml_root('<secure-properties:config name="SecureProps" key="key" file="file.enc"/>')
        self.assertTrue(code_reviewer._contains_secure_properties_config(root, NS_MAP))

    def test_contains_secure_properties_config_absent(self):
        root = self._create_xml_root('<flow name="test"/>')
        self.assertFalse(code_reviewer._contains_secure_properties_config(root, NS_MAP))

    # Example for one more component, e.g., sftp:listener-config (if there was such a check)
    # For now, let's test check_sftp for sftp:inbound-endpoint
    def test_check_sftp_valid(self):
        root = self._create_xml_root('<sftp:inbound-endpoint host="localhost" port="22" path="/"/>')
        issues = code_reviewer.check_sftp(root, NS_MAP)
        self.assertEqual(len(issues),0)

    def test_check_sftp_missing_host(self):
        root = self._create_xml_root('<sftp:inbound-endpoint port="22" path="/"/>')
        issues = code_reviewer.check_sftp(root, NS_MAP)
        self.assertIn("SFTP Inbound Endpoint is missing a host attribute.", issues)

    def test_check_http_response_valid(self):
        root = self._create_xml_root('<http:response-builder><http:status-code value="200"/></http:response-builder>')
        issues = code_reviewer.check_http_response(root, NS_MAP)
        self.assertEqual(len(issues), 0)

    def test_check_http_response_missing_status_code(self):
        root = self._create_xml_root('<http:response-builder></http:response-builder>')
        issues = code_reviewer.check_http_response(root, NS_MAP)
        self.assertIn("HTTP Response Builder is missing a status-code element.", issues)

    def test_check_scheduler_valid(self):
        # Assuming scheduler is within a flow/app context for the check function
        root = self._create_xml_root('<flow name="schedulerFlow"><scheduler:inbound-endpoint frequency="1000"/></flow>')
        issues = code_reviewer.check_scheduler(root, NS_MAP) # NS_MAP needs 'scheduler' if not already there
        self.assertEqual(len(issues), 0)

    def test_check_scheduler_missing_frequency(self):
        root = self._create_xml_root('<flow name="schedulerFlow"><scheduler:inbound-endpoint/></flow>')
        issues = code_reviewer.check_scheduler(root, NS_MAP)
        self.assertIn("Scheduler is missing a frequency attribute.", issues)

    # Add tests for:
    # check_concur, check_http_requester, check_ftp, check_smb, check_vm, check_s3, check_smtp

    def test_check_http_requester_valid(self):
        root = self._create_xml_root('<http:requester url="http://example.com" />')
        issues = code_reviewer.check_http_requester(root, NS_MAP)
        self.assertEqual(len(issues), 0)

    def test_check_http_requester_missing_url(self):
        root = self._create_xml_root('<http:requester />')
        issues = code_reviewer.check_http_requester(root, NS_MAP)
        self.assertIn("HTTP Requester is missing a URL attribute.", issues)

    def test_check_vm_valid(self):
        # Assuming vm:inbound-endpoint is the target for check_vm
        root = self._create_xml_root('<vm:inbound-endpoint queue-name="myQueue" max-retries="3"/>')
        issues = code_reviewer.check_vm(root, NS_MAP) # Ensure NS_MAP has 'vm' if needed
        self.assertEqual(len(issues), 0)

    def test_check_vm_missing_queue_name(self):
        root = self._create_xml_root('<vm:inbound-endpoint max-retries="3"/>')
        issues = code_reviewer.check_vm(root, NS_MAP)
        self.assertIn("VM Inbound Endpoint is missing a queue-name attribute.", issues)

    def test_check_vm_missing_max_retries(self):
        root = self._create_xml_root('<vm:inbound-endpoint queue-name="myQueue"/>')
        issues = code_reviewer.check_vm(root, NS_MAP)
        self.assertIn("VM Inbound Endpoint is missing a max-retries attribute.", issues)

    def test_check_concur_valid(self):
        root = self._create_xml_root('<concur:connector config-ref="Concur_Config"/>')
        issues = code_reviewer.check_concur(root, NS_MAP)
        self.assertEqual(len(issues), 0)

    def test_check_concur_missing_config_ref(self):
        root = self._create_xml_root('<concur:connector />')
        issues = code_reviewer.check_concur(root, NS_MAP)
        self.assertIn("Concur connector is missing a config-ref attribute.", issues)

    def test_check_ftp_valid(self):
        root = self._create_xml_root('<ftp:inbound-endpoint host="localhost" port="21" path="/files"/>')
        issues = code_reviewer.check_ftp(root, NS_MAP)
        self.assertEqual(len(issues), 0)

    def test_check_ftp_missing_attributes(self):
        root = self._create_xml_root('<ftp:inbound-endpoint path="/files"/>') # Missing host and port
        issues = code_reviewer.check_ftp(root, NS_MAP)
        self.assertIn("FTP Inbound Endpoint is missing a host attribute.", issues)
        self.assertIn("FTP Inbound Endpoint is missing a port attribute.", issues)

    def test_check_smb_valid(self):
        root = self._create_xml_root('<smb:inbound-endpoint host="localhost" port="445" username="user" path="/share"/>')
        issues = code_reviewer.check_smb(root, NS_MAP)
        self.assertEqual(len(issues), 0)

    def test_check_smb_missing_attributes(self):
        root = self._create_xml_root('<smb:inbound-endpoint path="/share"/>') # Missing host, port, username
        issues = code_reviewer.check_smb(root, NS_MAP)
        self.assertIn("SMB Inbound Endpoint is missing a host attribute.", issues)
        self.assertIn("SMB Inbound Endpoint is missing a port attribute.", issues)
        self.assertIn("SMB Inbound Endpoint is missing a username attribute.", issues)

    def test_check_s3_valid(self):
        root = self._create_xml_root('<s3:inbound-endpoint bucket-name="mybucket" access-key="key" path="/"/>')
        issues = code_reviewer.check_s3(root, NS_MAP)
        self.assertEqual(len(issues), 0)

    def test_check_s3_missing_attributes(self):
        root = self._create_xml_root('<s3:inbound-endpoint path="/"/>') # Missing bucket-name and access-key
        issues = code_reviewer.check_s3(root, NS_MAP)
        self.assertIn("S3 Inbound Endpoint is missing a bucket-name attribute.", issues)
        self.assertIn("S3 Inbound Endpoint is missing an access-key attribute.", issues)

    def test_check_smtp_valid(self):
        root = self._create_xml_root('<smtp:outbound-endpoint host="localhost" port="25" username="user"/>')
        issues = code_reviewer.check_smtp(root, NS_MAP)
        self.assertEqual(len(issues), 0)

    def test_check_smtp_missing_attributes(self):
        root = self._create_xml_root('<smtp:outbound-endpoint />') # Missing host, port, username
        issues = code_reviewer.check_smtp(root, NS_MAP)
        self.assertIn("SMTP Outbound Endpoint is missing a host attribute.", issues)
        self.assertIn("SMTP Outbound Endpoint is missing a port attribute.", issues)
        self.assertIn("SMTP Outbound Endpoint is missing a username attribute.", issues)


class TestReviewMuleSoftCode(unittest.TestCase):

    @patch('mule_validator.code_reviewer._contains_secure_properties_config')
    @patch('mule_validator.code_reviewer.check_smtp')
    @patch('mule_validator.code_reviewer.check_s3')
    @patch('mule_validator.code_reviewer.check_vm')
    @patch('mule_validator.code_reviewer.check_smb')
    @patch('mule_validator.code_reviewer.check_sftp')
    @patch('mule_validator.code_reviewer.check_ftp')
    @patch('mule_validator.code_reviewer.check_http_requester')
    @patch('mule_validator.code_reviewer.check_concur')
    @patch('mule_validator.code_reviewer.check_scheduler')
    @patch('mule_validator.code_reviewer.check_http_response')
    @patch('mule_validator.code_reviewer.check_dataweave')
    @patch('mule_validator.code_reviewer.check_logger')
    @patch('mule_validator.code_reviewer.check_http_listener')
    @patch('mule_validator.code_reviewer.check_flow_names')
    @patch('mule_validator.code_reviewer.etree.fromstring')
    @patch('builtins.open', new_callable=mock_open, read_data='<mule xmlns="http://www.mulesoft.org/schema/mule/core"></mule>')
    def test_review_mulesoft_code_aggregation_and_secure_props(
        self,
        mock_file_open,
        mock_et_fromstring,
        mock_check_flow_names,
        mock_check_http_listener,
        mock_check_logger,
        mock_check_dataweave,
        mock_check_http_response,
        mock_check_scheduler,
        mock_check_concur,
        mock_check_http_requester,
        mock_check_ftp,
        mock_check_sftp,
        mock_check_smb,
        mock_check_vm,
        mock_check_s3,
        mock_check_smtp,
        mock_contains_secure
    ):
        """Test that review_mulesoft_code aggregates issues from all check functions"""
        # Mock the root element that fromstring would return
        mock_root_element = MagicMock()
        mock_et_fromstring.return_value = mock_root_element

        # Set return values for the check functions we want to test
        mock_check_flow_names.return_value = ["flow name issue 1"]
        mock_check_http_listener.return_value = ["http listener issue 1"]
        mock_check_smtp.return_value = ["smtp issue 1"]
        
        # All other check functions return empty lists
        mock_check_logger.return_value = []
        mock_check_dataweave.return_value = []
        mock_check_http_response.return_value = []
        mock_check_scheduler.return_value = []
        mock_check_concur.return_value = []
        mock_check_http_requester.return_value = []
        mock_check_ftp.return_value = []
        mock_check_sftp.return_value = []
        mock_check_smb.return_value = []
        mock_check_vm.return_value = []
        mock_check_s3.return_value = []
        
        # Simulate secure properties config is found
        mock_contains_secure.return_value = True

        # Call the function under test
        issues, uses_secure = code_reviewer.review_mulesoft_code("dummy_file.xml")

        # Verify results
        self.assertTrue(uses_secure, "Should detect secure properties")
        self.assertIn("flow name issue 1", issues)
        self.assertIn("http listener issue 1", issues)
        self.assertIn("smtp issue 1", issues)
        self.assertEqual(len(issues), 3, f"Expected 3 issues, got {len(issues)}: {issues}")

        # Verify the check functions were called with correct arguments
        # The first argument should be the mock_root_element
        mock_check_flow_names.assert_called_once()
        call_args = mock_check_flow_names.call_args
        self.assertEqual(call_args[0][0], mock_root_element, 
                        "check_flow_names should be called with the root element")
        
        mock_check_http_listener.assert_called_once()
        call_args = mock_check_http_listener.call_args
        self.assertEqual(call_args[0][0], mock_root_element,
                        "check_http_listener should be called with the root element")
        
        mock_check_smtp.assert_called_once()
        call_args = mock_check_smtp.call_args
        self.assertEqual(call_args[0][0], mock_root_element,
                        "check_smtp should be called with the root element")
        
        mock_contains_secure.assert_called_once()
        call_args = mock_contains_secure.call_args
        self.assertEqual(call_args[0][0], mock_root_element,
                        "_contains_secure_properties_config should be called with the root element")
        
        # Verify fromstring was called to parse the XML
        mock_et_fromstring.assert_called_once()


    @patch('builtins.open')
    def test_review_mulesoft_code_file_read_error(self, mock_open_func):
        """Test handling of file read errors"""
        # Configure mock to raise IOError when open is called
        mock_open_func.side_effect = IOError("File read error")
        
        issues, uses_secure = code_reviewer.review_mulesoft_code("dummy_io_error.xml")
        
        self.assertFalse(uses_secure)
        self.assertEqual(len(issues), 1)
        self.assertIn("Error processing file dummy_io_error.xml", issues[0])
        self.assertIn("File read error", issues[0])


    @patch('mule_validator.code_reviewer.etree.fromstring', side_effect=etree.XMLSyntaxError("Test XMLSyntaxError", None, 1, 1))
    @patch('builtins.open', new_callable=mock_open, read_data='<mule><unclosed-tag></mule>')
    def test_review_mulesoft_code_xml_syntax_error(self, mock_file_open, mock_fromstring):
        """Test handling of XML syntax errors"""
        issues, uses_secure = code_reviewer.review_mulesoft_code("dummy_syntax_error.xml")
        
        self.assertFalse(uses_secure)
        self.assertEqual(len(issues), 1)
        self.assertIn("XML Syntax Error in file dummy_syntax_error.xml", issues[0])
        self.assertIn("Test XMLSyntaxError", issues[0])


class TestReviewAllFiles(unittest.TestCase):

    @patch('os.walk')
    @patch('mule_validator.code_reviewer.review_mulesoft_code')
    def test_review_all_files_basic_walk(self, mock_review_mulesoft_code, mock_os_walk):
        mock_os_walk.return_value = [
            ("/project", ["src", "target"], ["pom.xml"]),
            ("/project/src", ["main"], []),
            ("/project/src/main", ["mule", "resources"], []),
            ("/project/src/main/mule", [], ["flow1.xml", "flow2.xml", "api.munit"]), # api.munit should be skipped
            ("/project/target", [], ["my-app.jar"]) # target folder should be skipped
        ]

        # Define side effects for review_mulesoft_code
        def review_side_effect(file_path):
            if file_path == os.path.join("/project/src/main/mule", "flow1.xml"):
                return (["issue in flow1"], True) # Has secure properties
            elif file_path == os.path.join("/project/src/main/mule", "flow2.xml"):
                return ([], False) # No issues, no secure properties
            return ([], False) # Default for any other unexpected calls

        mock_review_mulesoft_code.side_effect = review_side_effect

        all_issues_data, project_uses_secure = code_reviewer.review_all_files("/project")
        
        self.assertTrue(project_uses_secure)
        # FIXED: Only flow1.xml has issues, so only 1 item in results
        self.assertEqual(len(all_issues_data), 1) # Only flow1.xml with its issue
        
        # Check content of all_issues_data - expecting [file_name, severity, issue_description]
        self.assertEqual(all_issues_data[0][0], "flow1.xml")
        self.assertEqual(all_issues_data[0][1], "WARNING")
        self.assertEqual(all_issues_data[0][2], "issue in flow1")

        # Assert review_mulesoft_code was called for the correct files
        expected_calls = [
            unittest.mock.call(os.path.join("/project/src/main/mule", "flow1.xml")),
            unittest.mock.call(os.path.join("/project/src/main/mule", "flow2.xml"))
        ]
        mock_review_mulesoft_code.assert_has_calls(expected_calls, any_order=True)
        self.assertEqual(mock_review_mulesoft_code.call_count, 2) # Both files should be processed

    @patch('os.walk')
    @patch('mule_validator.code_reviewer.review_mulesoft_code')
    def test_review_all_files_no_xml_files(self, mock_review_mulesoft_code, mock_os_walk):
        mock_os_walk.return_value = [
            ("/project/src/main/mule", [], ["readme.txt"]),
        ]
        all_issues_data, project_uses_secure = code_reviewer.review_all_files("/project")
        self.assertFalse(project_uses_secure)
        self.assertEqual(len(all_issues_data), 0)
        mock_review_mulesoft_code.assert_not_called()

    @patch('os.walk')
    @patch('mule_validator.code_reviewer.review_mulesoft_code')
    def test_review_all_files_skip_target_test_pom(self, mock_review_mulesoft_code, mock_os_walk):
        mock_os_walk.return_value = [
            ("/project", [], ["pom.xml"]), # Should be skipped
            ("/project/src/main/mule", [], ["main.xml"]),
            ("/project/target", [], ["skip_me.xml"]), # Should be skipped
            ("/project/src/test/munit", [], ["test_skip.xml"]), # Should be skipped
            ("/project/src/main/resources/munit", [], ["another_munit.xml"]) # Should be skipped as 'munit' in name
        ]
        mock_review_mulesoft_code.return_value = ([], False)

        code_reviewer.review_all_files("/project")

        # Check that review_mulesoft_code was only called for main.xml
        mock_review_mulesoft_code.assert_called_once_with(os.path.join("/project/src/main/mule", "main.xml"))


if __name__ == '__main__':
    unittest.main(verbosity=2)
