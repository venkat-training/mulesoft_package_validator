import unittest
from mule_validator.html_reporter import generate_html_report

class TestHtmlReporter(unittest.TestCase):

    def setUp(self):
        self.sample_template_string = """
        <h1>Report</h1>
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
        """

        self.all_placeholders = [
            "{{code_review_issues_table}}",
            "{{yaml_validation_results_table}}",
            "{{dependency_validation_results_table}}",
            "{{flow_validation_results_table}}",
            "{{api_validation_results_table}}",
            "{{components_validation_results_table}}",
            "{{secure_properties_status}}"
        ]

    def test_generate_html_report_with_data(self):
        sample_all_results = {
            'code_reviewer_issues': [["file1.xml", "Error", "Too complex"]],
            'yaml_validation': ["yaml_error1: value", "yaml_error2: value"],
            'dependency_validation': {"dep1": "Unused", "dep2": "Used"},
            'flow_validation': [{"flowName": "flow1", "issue": "No error handler"}],
            'api_validation': [{"apiName": "api1", "raml_file": "api1.raml", "status": "Missing flow"}],
            'components_validator': ["component_error1", "component_error2"],
            'project_uses_secure_properties': True
        }

        generated_html = generate_html_report(sample_all_results, self.sample_template_string)

        for placeholder in self.all_placeholders:
            self.assertNotIn(placeholder, generated_html, f"Placeholder {placeholder} was not replaced.")

        self.assertIn("<td>file1.xml</td>", generated_html)
        self.assertIn("<li>yaml_error1: value</li>", generated_html)
        self.assertIn("<td>dep1</td><td>Unused</td>", generated_html) # From _format_data_to_html dict handling
        self.assertIn("<td>flow1</td>", generated_html)
        self.assertIn("<td>api1</td>", generated_html)
        self.assertIn("<li>component_error1</li>", generated_html)
        self.assertIn("<p>True</p>", generated_html) # project_uses_secure_properties

    def test_generate_html_report_empty_and_missing_data(self):
        sample_all_results_empty = {
            'code_reviewer_issues': [],
            'yaml_validation': None, # Test None
            'dependency_validation': {},
            'flow_validation': [],
            'api_validation': None, # Test None
            'components_validator': [],
            'project_uses_secure_properties': False
        }

        generated_html = generate_html_report(sample_all_results_empty, self.sample_template_string)

        for placeholder in self.all_placeholders:
            self.assertNotIn(placeholder, generated_html, f"Placeholder {placeholder} was not replaced (empty data test).")

        # Check for specific "no data" messages based on html_reporter.py implementation
        self.assertIn("<p>No code review issues found.</p>", generated_html)
        self.assertIn("<p>No data available.</p>", generated_html) # For yaml_validation (None) and dependency_validation ({})
        self.assertIn("<p>No flow validation data available or no issues found.</p>", generated_html) # For flow_validation ([])
        self.assertIn("<p>No API validation data available or no issues found.</p>", generated_html) # For api_validation (None)
        self.assertIn("<p>No data available.</p>", generated_html) # For components_validator ([])
        self.assertIn("<p>False</p>", generated_html) # project_uses_secure_properties

    def test_generate_html_report_mixed_data_some_missing_keys(self):
        # Test with some keys completely missing from all_results
        sample_all_results_partial = {
            'code_reviewer_issues': [["file2.xml", "Warning", "Magic number"]],
            'project_uses_secure_properties': True
            # Other keys are missing
        }

        generated_html = generate_html_report(sample_all_results_partial, self.sample_template_string)

        # Check that the provided data is present
        self.assertIn("<td>file2.xml</td>", generated_html)
        self.assertIn("<p>True</p>", generated_html)
        self.assertNotIn("{{code_review_issues_table}}", generated_html)
        self.assertNotIn("{{secure_properties_status}}", generated_html)

        # Check that missing keys are replaced with "Data not available" (fallback in generate_html_report)
        # or specific "no data" messages if those placeholders were hit by earlier specific replacements
        # The fallback `html_content.replace('{{placeholder}}', "<p>Data not available.</p>")` is key here.
        self.assertIn("<p>Data not available.</p>", generated_html.lower()) # Check for the fallback message
        
        # Specifically check placeholders that would use the fallback
        self.assertTrue(
            "<p>Data not available.</p>" in generated_html or
            "<p>No data available.</p>" in generated_html or # Specific message from _format_data_to_html
            "no issues found" in generated_html.lower() # Generic part of "no issues" messages
        )
        
        # Ensure no raw placeholders remain for sections that were missing from input
        missing_data_placeholders = [
            "{{yaml_validation_results_table}}",
            "{{dependency_validation_results_table}}",
            "{{flow_validation_results_table}}",
            "{{api_validation_results_table}}",
            "{{components_validation_results_table}}"
        ]
        for placeholder in missing_data_placeholders:
             self.assertNotIn(placeholder, generated_html)


if __name__ == '__main__':
    unittest.main()
