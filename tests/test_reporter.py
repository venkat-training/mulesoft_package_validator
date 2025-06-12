import unittest
from unittest.mock import patch, MagicMock
from io import StringIO
import sys

# Assuming reporter.py is in mule_validator directory
from mule_validator import reporter

class TestConsoleReporter(unittest.TestCase):

    def setUp(self):
        self.held_stdout = sys.stdout
        sys.stdout = StringIO()
        # Mock logger for the reporter module
        self.logger_patch = patch('mule_validator.reporter.logger', MagicMock())
        self.mock_logger = self.logger_patch.start()

    def tearDown(self):
        sys.stdout = self.held_stdout
        self.logger_patch.stop()

    def test_report_empty_results(self):
        reporter.generate_console_report({})
        output = sys.stdout.getvalue()
        self.assertIn("VALIDATION REPORT", output)
        self.assertIn("No validation results to report.", output)
        self.assertIn("END OF REPORT", output)

    def test_report_yaml_validation_structure_and_security(self):
        all_results = {
            'yaml_validation': [
                {'file_name': 'config-prod.yaml', 'status': 'Valid', 'message': '', 'type': 'Mandatory'},
                {'file_name': 'config-dev.yaml', 'status': 'InvalidSyntax', 'message': 'Bad indent', 'type': 'Optional'}, # Corrected status
                {'file_name': 'secrets.yaml', 'status': 'SecurityWarning', 'message': 'Potential secret at path user.password. Key: password. Type: Keyword. Description: Contains sensitive keyword.', # Shortened for test
                 'type': 'Optional', # Assuming security warnings can also be optional/mandatory for file presence
                 'details': {'path': 'user.password', 'key': 'password', 'value_excerpt': 'secret123...', 'issue_type': 'Keyword'}
                }
            ]
        }
        reporter.generate_console_report(all_results)
        output = sys.stdout.getvalue()

        self.assertIn("--- YAML VALIDATION ---", output)
        self.assertIn("Mandatory Configuration Files", output)
        self.assertIn("config-prod.yaml", output)
        self.assertIn("Optional Configuration Files", output)
        self.assertIn("config-dev.yaml", output)
        self.assertIn("Bad indent", output)
        self.assertIn("YAML Security Warnings:", output)
        self.assertIn("[SECURITY WARNING] (YAML Secret)", output)
        self.assertIn("File: secrets.yaml", output)
        self.assertIn("Location: user.password", output)
        self.assertIn("Value Excerpt: \"secret123...\"", output)
        self.assertIn("TOTAL SECURITY WARNINGS FOUND: 1", output)


    def test_report_yaml_resources_dir_error(self):
        all_results = {
            'yaml_validation': [
                {'file_name': 'N/A', 'status': 'Error', 'type': 'Setup', 'message': 'Resources directory not found...'}
            ]
        }
        reporter.generate_console_report(all_results)
        output = sys.stdout.getvalue()
        self.assertIn("--- YAML VALIDATION ---", output)
        self.assertIn("ERROR: Resources directory not found...", output)
        self.assertNotIn("Mandatory Configuration Files:", output)


    def test_report_dependency_validation_with_pom_secrets(self):
        all_results = {
            'dependency_validation': {
                'unused_dependencies': ['com.example:dep1'],
                'build_size_mb': 150.0,
                'size_ok': False,
                'max_size_mb': 100,
                'pom_security_warnings': [
                    {'file_path': 'pom.xml', 'xml_path': 'project.properties.db.password',
                     'message': 'Hardcoded password', 'value_excerpt': 'pass123...', 'issue_type': 'Hardcoded Secret'}
                ]
            }
        }
        reporter.generate_console_report(all_results)
        output = sys.stdout.getvalue()

        self.assertIn("--- DEPENDENCY VALIDATION ---", output)
        self.assertIn("Build Size: 150.00 MB (Max Allowed: 100 MB) - Status: Exceeded Limit", output)
        self.assertIn("Unused Dependencies:", output)
        self.assertIn("- com.example:dep1", output)
        self.assertIn("POM Security Warnings:", output)
        self.assertIn("[SECURITY WARNING] (POM Secret)", output)
        self.assertIn("File: pom.xml", output)
        self.assertIn("Location: Element: <project.properties.db.password>", output)
        self.assertIn("TOTAL SECURITY WARNINGS FOUND: 1", output)


    def test_report_flow_validation_error_message(self):
        all_results = {
            'flow_validation': {
                'total_counts': None,
                'message': "Mule source directory does not exist: path/to/src/main/mule",
                'flows_ok': False, 'sub_flows_ok': False, 'components_ok': False,
                'max_flows_limit': 'N/A', 'max_sub_flows_limit': 'N/A', 'max_components_limit': 'N/A'
            }
        }
        reporter.generate_console_report(all_results)
        output = sys.stdout.getvalue()
        self.assertIn("--- FLOW VALIDATION ---", output)
        self.assertIn("ERROR: Mule source directory does not exist: path/to/src/main/mule", output)
        self.assertNotIn("| Category", output) # No table

    def test_report_api_validation_structure(self):
        # Assuming api_validator returns a dict like this based on its docstring
        all_results = {
            'api_validation': {
                'api_spec_dependency': "group:artifact:1.0:raml:zip",
                'api_spec_zip_found': True,
                'apikit_router_file': "my-api.xml",
                'apikit_router_found': True,
                'notes': ["Optional note here"]
            }
        }
        # The current reporter.py has a simple print for api_validation dicts
        # It doesn't iterate 'notes'. It prints the dict as-is.
        reporter.generate_console_report(all_results)
        output = sys.stdout.getvalue()
        self.assertIn("--- API VALIDATION ---", output)
        # This will print the string representation of the dict.
        self.assertIn("'api_spec_dependency': 'group:artifact:1.0:raml:zip'", output)
        self.assertIn("'notes': ['Optional note here']", output)


    def test_report_code_reviewer_structure_and_security(self):
        # This test assumes code_reviewer results are structured as list of dicts
        # with 'type', 'file_path', 'message', etc.
        all_results = {
            'code_reviewer': [
                {'file_path': 'a.xml', 'type': 'XMLSyntaxError', 'message': 'bad xml'},
                {'file_path': 'b.xml', 'type': 'CodeReviewIssue', 'message': 'Flow name too long'},
                {'file_path': 'b.xml', 'type': 'HardcodedSecretXML',
                 'xml_path': 'db.password', 'attribute_name': None,
                 'value_excerpt': 'secret...', 'message': 'Hardcoded password in text',
                 'issue_type': 'Hardcoded Secret'} # issue_type for _print_security_warning
            ]
        }
        reporter.generate_console_report(all_results)
        output = sys.stdout.getvalue()
        self.assertIn("--- CODE REVIEWER ---", output)
        self.assertIn("File Processing Errors (Code Review):", output)
        self.assertIn("File: a.xml", output)
        self.assertIn("Error Type: XMLSyntaxError", output)
        self.assertIn("Standard Code Review Issues by File:", output)
        self.assertIn("File: b.xml", output)
        self.assertIn("- Flow name too long", output)
        self.assertIn("XML Code Security Warnings:", output)
        self.assertIn("[SECURITY WARNING] (Hardcoded Secret)", output) # issue_type used here
        self.assertIn("File: b.xml", output)
        self.assertIn("Location: Element: <db.password>", output)
        self.assertIn("TOTAL SECURITY WARNINGS FOUND: 1", output)

    def test_report_logging_validation_fallback(self):
        # Logging validation results use the fallback printing for now
        all_results = {
            'logging_validation': {
                "logger_issues": [{"file": "f.xml", "flow": "myFlow", "issue": "DEBUG found"}],
                "log4j_warnings": ["Root is DEBUG"]
            }
        }
        reporter.generate_console_report(all_results)
        output = sys.stdout.getvalue()
        self.assertIn("--- LOGGING VALIDATION ---", output)
        # Check for string representation of the dict
        self.assertIn("'logger_issues': ", output)
        self.assertIn("'log4j_warnings': ['Root is DEBUG']", output)
        self.assertIn("DEBUG found", output)


    def test_report_total_security_warnings_multiple_sections(self):
        all_results = {
            'yaml_validation': [
                {'file_name': 's.yaml', 'status': 'SecurityWarning', 'type': 'Optional',
                 'details': {'path': 'key', 'value_excerpt': 's...', 'issue_type': 'Generic'}}
            ],
            'dependency_validation': {
                'pom_security_warnings': [
                    {'file_path': 'pom.xml', 'xml_path': 'prop', 'message': 'secret prop', 'issue_type': 'Hardcoded Secret'}
                ]
            },
             'code_reviewer': [
                {'file_path': 'b.xml', 'type': 'HardcodedSecretXML',
                 'xml_path': 'db.password', 'message': 'Hardcoded password in text',
                 'issue_type': 'Hardcoded Secret'}
            ]
        }
        reporter.generate_console_report(all_results)
        output = sys.stdout.getvalue()
        self.assertIn("TOTAL SECURITY WARNINGS FOUND: 3", output)


if __name__ == '__main__':
    unittest.main()
