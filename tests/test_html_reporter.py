import unittest
from unittest.mock import patch, MagicMock
import subprocess
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

        # List of all placeholders to check replacement
        self.all_placeholders = [
            "{{git_branch_name}}",
            "{{code_review_issues_table}}",
            "{{yaml_validation_results_table}}",
            "{{dependency_validation_results_table}}",
            "{{flow_validation_results_table}}",
            "{{api_validation_results_table}}",
            "{{components_validation_results_table}}",
            "{{secure_properties_status}}",
            "{{logging_validation_results_table}}",
            "{{report_start_time}}",
            "{{report_end_time}}",
            "{{report_duration}}"
        ]

    @patch('mule_validator.html_reporter.get_current_git_branch', return_value="main")
    def test_generate_html_report_with_data(self, mock_get_branch_call):
        sample_all_results = {
            'code_reviewer_issues': [["file1.xml", "Error", "Too complex"]],
            'yaml_validation': [["yaml_error1", "Syntax Invalid", "details..."]],
            'dependency_validation': {"pom.xml": {"missing_jars": ["missing.jar"]}},
            'flow_validation': {"total_counts": {"flows": 10}},
            'api_validation': {"api_spec_dependency": "spec:ok"},
            'components_validator': ["comp1", "comp2"],
            'project_uses_secure_properties': True,
            'logging_validation': {"logger_issues": [{"file": "f1.xml", "flow": "flow1", "issue": "DEBUG"}],
                                   "log4j_warnings": ["Root logger is DEBUG"]},
            'git_branch_name': "main",
            'report_start_time': "2023-01-01 10:00:00",
            'report_end_time': "2023-01-01 10:00:30",
            'report_duration': "0:00:30"
        }

        generated_html = generate_html_report(sample_all_results, self.sample_template_string)

        # Ensure all placeholders replaced
        for placeholder_tag in self.all_placeholders:
            self.assertNotIn(placeholder_tag, generated_html)

        # Spot checks
        self.assertIn("file1.xml", generated_html)
        self.assertIn("yaml_error1", generated_html)
        self.assertIn("pom.xml", generated_html)
        self.assertIn("10", generated_html)
        self.assertIn("spec:ok", generated_html)
        self.assertIn("comp1", generated_html)
        self.assertIn("<p>True</p>", generated_html)
        self.assertIn("DEBUG", generated_html)
        self.assertIn("Root logger is DEBUG", generated_html)
        self.assertIn("Branch: main", generated_html)
        self.assertIn("2023-01-01 10:00:30", generated_html)
        mock_get_branch_call.assert_not_called()  # Provided explicitly

    @patch('mule_validator.html_reporter.get_current_git_branch', return_value="develop")
    def test_generate_html_report_empty_and_missing_data(self, mock_get_branch_call):
        sample_all_results_empty = {
            'code_reviewer_issues': [],
            'yaml_validation': None,
            'dependency_validation': {},
            'flow_validation': [],
            'api_validation': {},
            # components_validator missing
            'project_uses_secure_properties': False,
            'logging_validation': {"logger_issues": [], "log4j_warnings": []},
            'report_start_time': "N/A",
            'report_end_time': "N/A",
            'report_duration': "N/A"
        }

        generated_html = generate_html_report(sample_all_results_empty, self.sample_template_string)

        # Ensure all placeholders replaced
        for placeholder_tag in self.all_placeholders:
            self.assertNotIn(placeholder_tag, generated_html)

        # Check fallback content
        self.assertIn("<p>No code review issues detected.</p>", generated_html)
        self.assertIn("<p>No YAML validation issues found.</p>", generated_html)
        self.assertIn("<p>No dependency issues found.</p>", generated_html)
        self.assertIn("<p>No flow validation issues found.</p>", generated_html)
        self.assertIn("<p>No API validation issues found.</p>", generated_html)
        self.assertIn("<p>Data not available.</p>", generated_html)  # components placeholder
        self.assertIn("<p>False</p>", generated_html)
        self.assertIn("<p>No logging issues detected.</p>", generated_html)
        self.assertIn("Branch: develop", generated_html)
        mock_get_branch_call.assert_called_once()

    @patch('mule_validator.html_reporter.get_current_git_branch', return_value="feature/xyz")
    def test_generate_html_report_partial_data(self, mock_get_branch_call):
        sample_all_results_partial = {
            'code_reviewer_issues': [["file2.xml", "Warning", "Magic number"]],
            'project_uses_secure_properties': True,
            'git_branch_name': "supplied-branch"
        }

        generated_html = generate_html_report(sample_all_results_partial, self.sample_template_string)

        self.assertIn("file2.xml", generated_html)
        self.assertIn("<p>True</p>", generated_html)
        self.assertIn("<p>No YAML validation issues found.</p>", generated_html)
        self.assertIn("<p>No dependency issues found.</p>", generated_html)
        self.assertIn("<p>No flow validation issues found.</p>", generated_html)
        self.assertIn("<p>No API validation issues found.</p>", generated_html)
        self.assertIn("<p>No logging issues detected.</p>", generated_html)
        self.assertIn("<p>Data not available.</p>", generated_html)
        self.assertIn("Branch: supplied-branch", generated_html)
        mock_get_branch_call.assert_not_called()

if __name__ == "__main__":
    unittest.main()
