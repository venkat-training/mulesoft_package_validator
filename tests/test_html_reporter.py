import unittest
from unittest.mock import patch, MagicMock
import subprocess # For testing get_current_git_branch exceptions
from mule_validator.html_reporter import generate_html_report, get_current_git_branch

class TestGetCurrentGitBranch(unittest.TestCase):

    @patch('subprocess.run')
    def test_get_current_git_branch_success(self, mock_subprocess_run):
        mock_process_result = MagicMock()
        mock_process_result.stdout = "feature/test-branch\n"
        mock_subprocess_run.return_value = mock_process_result

        branch_name = get_current_git_branch()
        self.assertEqual(branch_name, "feature/test-branch")
        mock_subprocess_run.assert_called_once_with(
            ['git', 'rev-parse', '--abbrev-ref', 'HEAD'],
            capture_output=True, text=True, check=True, timeout=5
        )

    @patch('subprocess.run', side_effect=subprocess.CalledProcessError(returncode=1, cmd="git ...", stderr="git error"))
    def test_get_current_git_branch_called_process_error(self, mock_subprocess_run):
        branch_name = get_current_git_branch()
        self.assertEqual(branch_name, "Unknown")

    @patch('subprocess.run', side_effect=FileNotFoundError("git command not found"))
    def test_get_current_git_branch_file_not_found(self, mock_subprocess_run):
        branch_name = get_current_git_branch()
        self.assertEqual(branch_name, "Unknown")

    @patch('subprocess.run', side_effect=subprocess.TimeoutExpired(cmd="git ...", timeout=5))
    def test_get_current_git_branch_timeout(self, mock_subprocess_run):
        branch_name = get_current_git_branch()
        self.assertEqual(branch_name, "Unknown")

    @patch('subprocess.run')
    def test_get_current_git_branch_empty_output(self, mock_subprocess_run):
        mock_process_result = MagicMock()
        mock_process_result.stdout = "\n" # Empty or just newline
        mock_subprocess_run.return_value = mock_process_result
        branch_name = get_current_git_branch()
        # Assuming .strip() results in empty string for just newline, which is fine.
        # If it was truly empty, it's still "Unknown" if check=True would fail on that.
        # But `check=True` means non-zero exit code. Empty stdout with 0 exit is possible.
        self.assertEqual(branch_name, "") # Or "Unknown" depending on how robust it should be for empty but successful.
                                          # Current impl: `strip()` on empty string is empty string.

class TestHtmlReporter(unittest.TestCase):

    def setUp(self):
        self.sample_template_string = """
        <h1>Report</h1>
        <p>Branch: {{git_branch_name}}</p>
        <h2>Code Review</h2>
        <div id="code-review">{{code_review_issues_table}}</div>
        <h2>YAML Validation</h2>
        <div id="yaml-validation">{{yaml_validation_results_table}}</div>
        <h2>Dependency Validation</h2>
        <div id="dependency-validation">{{dependency_validation_results_table}}</div>
        <h2>Flow Validation</h2>
        <div id="flow-validation">{{flow_validation_results_table}}</div>
        <h2>API Validation</h2>
        <div id="api-validation">{{api_validation_results_table}}</div>
        <h2>Components Validation</h2>
        <div id="components-validation">{{components_validation_results_table}}</div>
        <h2>Secure Properties</h2>
        <div id="secure-properties">{{secure_properties_status}}</div>
        <h2>Logging Validation</h2>
        <div id="logging-validation">{{logging_validation_results_table}}</div>
        <hr>
        <p>Report generated at: {{report_end_time}} (Duration: {{report_duration}})</p>
        """

        self.all_placeholders = [
            "{{git_branch_name}}",
            "{{code_review_issues_table}}",
            "{{yaml_validation_results_table}}",
            "{{dependency_validation_results_table}}",
            "{{flow_validation_results_table}}",
            "{{api_validation_results_table}}",
            "{{components_validation_results_table}}", # This placeholder is in template but not handled by html_reporter.py
            "{{secure_properties_status}}",
            "{{logging_validation_results_table}}",
            "{{report_start_time}}", # Though not in sample template directly, it's a standard field
            "{{report_end_time}}",
            "{{report_duration}}"
        ]
        # Note: 'components_validation_results_table' is in the test template but not explicitly handled
        # by the generate_html_report function in html_reporter.py. It will use the fallback.

    @patch('mule_validator.html_reporter.get_current_git_branch', return_value="main") # Mock get_current_git_branch
    def test_generate_html_report_with_data(self, mock_get_branch_call): # Renamed mock
        sample_all_results = {
            'code_reviewer_issues': [["file1.xml", "Error", "Too complex"]],
            'yaml_validation': [["yaml_error1", "Syntax Invalid", "details..."]], # list of lists
            'dependency_validation': { # Dict of dicts
                "pom.xml": {
                    "missing_jars": ["missing.jar"],
                    "unresolved_dependencies": ["unresolved:dep"],
                    "duplicate_dependencies": ["duplicate:dep"]
                }
            },
            'flow_validation': {"total_counts": {"flows": 10}, "flows_ok": True, "invalid_flow_names": []}, # Dict structure
            'api_validation': {"api_spec_dependency": "spec:ok", "api_spec_zip_found": True, "apikit_router_found": True, "notes":[]}, # Dict structure
            # 'components_validator': ["component_error1", "component_error2"], # This key is not processed by html_reporter
            'project_uses_secure_properties': True,
            'logging_validation': {
                "logger_issues": [{"file": "f1.xml", "flow": "flow1", "issue": "DEBUG found"}],
                "log4j_warnings": ["Root logger is DEBUG"]
            },
            'git_branch_name': "main", # Explicitly provide for clarity, though mocked too
            'report_start_time': "2023-01-01 10:00:00",
            'report_end_time': "2023-01-01 10:00:30",
            'report_duration': "0:00:30"
        }

        generated_html = generate_html_report(sample_all_results, self.sample_template_string)

        # Check that all placeholders are replaced
        for placeholder_tag in self.all_placeholders:
            if placeholder_tag == "{{components_validation_results_table}}" and 'components_validator' not in sample_all_results:
                 # This one is not handled by html_reporter.py, so it will hit the fallback
                self.assertIn("<p>Data not available.</p>", generated_html)
                self.assertNotIn(placeholder_tag, generated_html)
                continue
            self.assertNotIn(placeholder_tag, generated_html, f"Placeholder {placeholder_tag} was not replaced.")

        # Spot check some content
        self.assertIn("<td>file1.xml</td>", generated_html) # Code Review
        self.assertIn("<td>yaml_error1</td>", generated_html) # YAML
        self.assertIn("<h4>pom.xml</h4>", generated_html) # Dependency
        self.assertIn("<td>Missing Artifact</td><td>missing.jar</td>", generated_html)
        self.assertIn("<td>10</td>", generated_html) # Flow validation (count)
        self.assertIn("spec:ok", generated_html) # API validation (api_spec_dependency)
        self.assertIn("<p>True</p>", generated_html) # Secure Properties
        self.assertIn("<h4>Logger Issues</h4>", generated_html) # Logging
        self.assertIn("<td>DEBUG found</td>", generated_html)
        self.assertIn("<h4>Log4j Warnings</h4>", generated_html)
        self.assertIn("<li>Root logger is DEBUG</li>", generated_html)
        self.assertIn("Branch: main", generated_html)
        self.assertIn("2023-01-01 10:00:00", generated_html)
        self.assertIn("0:00:30", generated_html)
        mock_get_branch_call.assert_not_called() # Branch name was provided in all_results

    @patch('mule_validator.html_reporter.get_current_git_branch', return_value="develop")
    def test_generate_html_report_empty_and_missing_data(self, mock_get_branch_call):
        sample_all_results_empty = {
            'code_reviewer_issues': [],
            'yaml_validation': None,
            'dependency_validation': {},
            'flow_validation': [], # Empty list for flow_validation
            'api_validation': {},  # Empty dict for api_validation
            # 'components_validator' key missing
            'project_uses_secure_properties': False,
            'logging_validation': {"logger_issues": [], "log4j_warnings": []},
            # 'git_branch_name' missing, so get_current_git_branch will be called
            'report_start_time': "N/A",
            'report_end_time': "N/A",
            'report_duration': "N/A"
        }

        generated_html = generate_html_report(sample_all_results_empty, self.sample_template_string)

        for placeholder_tag in self.all_placeholders:
            self.assertNotIn(placeholder_tag, generated_html, f"Placeholder {placeholder_tag} was not replaced (empty/missing data).")

        self.assertIn("<p>No code review issues found.</p>", generated_html)
        self.assertIn("<p>No YAML validation issues found.</p>", generated_html) # Handles None by specific message
        self.assertIn("<p>No dependency issues found.</p>", generated_html) # Handles {} by specific message
        self.assertIn("<p>No flow validation issues found.</p>", generated_html) # Handles [] by specific message
        self.assertIn("<p>No API validation issues found.</p>", generated_html) # Handles {} by specific message
        self.assertIn("<p>Data not available.</p>", generated_html) # Fallback for components_validation_results_table
        self.assertIn("<p>False</p>", generated_html) # Secure Properties
        self.assertIn("<p>No logging issues found.</p>", generated_html) # Logging with empty sub-lists
        self.assertIn("Branch: develop", generated_html)
        mock_get_branch_call.assert_called_once() # Called because 'git_branch_name' was not in all_results

    @patch('mule_validator.html_reporter.get_current_git_branch', return_value="feature/xyz")
    def test_generate_html_report_mixed_data_some_missing_keys(self, mock_get_branch_call):
        sample_all_results_partial = {
            'code_reviewer_issues': [["file2.xml", "Warning", "Magic number"]],
            'project_uses_secure_properties': True,
            # 'git_branch_name' is supplied, so mock should not be called
            'git_branch_name': "supplied-branch"
            # Other keys (yaml, dependency, flow, api, logging, times) are missing
        }

        generated_html = generate_html_report(sample_all_results_partial, self.sample_template_string)

        self.assertIn("<td>file2.xml</td>", generated_html)
        self.assertIn("<p>True</p>", generated_html)
        self.assertNotIn("{{code_review_issues_table}}", generated_html)
        self.assertNotIn("{{secure_properties_status}}", generated_html)

        # Check that missing keys are replaced with their specific "no issues found" or fallback messages
        self.assertIn("<p>No YAML validation issues found.</p>", generated_html)
        self.assertIn("<p>No dependency issues found.</p>", generated_html)
        self.assertIn("<p>No flow validation issues found.</p>", generated_html)
        self.assertIn("<p>No API validation issues found.</p>", generated_html)
        self.assertIn("<p>No logging issues found.</p>", generated_html)
        self.assertIn("<p>Data not available.</p>", generated_html) # Fallback for components_validation_results_table and times

        self.assertIn("Branch: supplied-branch", generated_html)
        mock_get_branch_call.assert_not_called() # Not called as branch name was in all_results

    def test_html_report_handles_api_validation_list_format_deprecated(self):
        # Test the deprecated list format for api_validation for backward compatibility in _format_data_to_html
        # The main generate_html_report has specific handling for list of dicts for api_validation
        # This test ensures that if api_validation was a simple list of strings, it's handled by _format_data_to_html
        sample_all_results = {
            'api_validation': ["Old API issue 1", "Old API issue 2"],
            'git_branch_name': 'test-branch'
        }
        generated_html = generate_html_report(sample_all_results, self.sample_template_string)
        self.assertIn("<li>Old API issue 1</li>", generated_html)
        self.assertIn("<li>Old API issue 2</li>", generated_html)

    def test_html_report_handles_flow_validation_dict_format(self):
        # Test the current dictionary format for flow_validation
        sample_all_results = {
            'flow_validation': {
                'total_counts': {'flows': 5, 'sub_flows': 1, 'components': 15},
                'flows_ok': True, 'sub_flows_ok': True, 'components_ok': True,
                'flow_names_camel_case_ok': False,
                'invalid_flow_names': ['badName', 'Another_Bad_Name'],
                'max_flows_limit': 100, 'max_sub_flows_limit':50, 'max_components_limit':500
            },
            'git_branch_name': 'test-branch'
        }
        # The current html_reporter doesn't tabulate this dict directly for flow_validation
        # It uses _format_data_to_html if it's not a list of dicts.
        # Let's check if it gets formatted reasonably by _format_data_to_html
        generated_html = generate_html_report(sample_all_results, self.sample_template_string)
        self.assertIn("<td>total_counts</td>", generated_html) # Key from the dict
        self.assertIn("<td>invalid_flow_names</td>", generated_html)
        self.assertIn("badName", generated_html) # Part of the value for invalid_flow_names

if __name__ == '__main__':
    unittest.main()
