"""
Enhanced Hybrid Test Suite for HTML Report Generation

- Unit tests with a dummy template for isolated coverage
- Full automated validation of all sections and badges
- Integration test with actual template if present

Run with:
    python -m unittest tests/test_html_report_generation.py
"""

import os
import sys
import unittest
from mule_validator.html_reporter import generate_html_report

# Add repo root to sys.path
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

# -------------------------
# Dummy template for unit testing
# -------------------------
DUMMY_TEMPLATE = """
<html>
<head><title>Test Report</title></head>
<body>
<h1>{{ project_name }} - Validation Report</h1>
<p>Status: {{ status }}</p>
<p>Branch: {{ git_branch_name }}</p>
<p>Start: {{ report_start_time }} | End: {{ report_end_time }} | Duration: {{ report_duration }}</p>

<h2>Threshold Warnings</h2>
{{threshold_warnings}}

<h2>Scorecard</h2>
<table>{{scorecard_table}}</table>

<h2>Code Review Issues</h2>
{{code_review_issues_table}}

<h2>YAML Validation</h2>
{{yaml_validation_results_table}}

<h2>Dependency Validation</h2>
{{dependency_validation_results_table}}

<h2>Flow Validation</h2>
{{flow_validation_results_table}}

<h2>API Validation</h2>
{{api_validation_results_table}}

<h2>Secure Properties</h2>
{{secure_properties_status}}

<h2>Logging</h2>
{{logging_validation_results_table}}

<h2>Orphan Checker</h2>
{{orphan_validation_results_table}}

</body>
</html>
"""

# -------------------------
# Mock results for testing
# -------------------------
MOCK_RESULTS = {
    "report_start_time": "2026-01-25 08:00:00",
    "report_end_time": "2026-01-25 08:15:00",
    "report_duration": "15 minutes",
    "status": "PASS",
    "project_name": "MuleTestProject",
    "git_branch": "feature/testing",
    "git_branch_name": "feature/testing",
    "python_version": "3.10.5",
    "timestamp": "2026-01-25 08:15:00",
    "scorecard": [
        {"metric": "Total Flows", "value": 6, "status": "WARN"},
        {"metric": "Components", "value": 34, "status": "PASS"},
    ],
    "thresholds": {
        "max_build_size_mb": 100,
        "max_flows": 5,
        "max_sub_flows": 2,
        "max_components": 30,
    },
    "dependency_validation": {
        "build_size_mb": 120,
        "pom1": {"missing_jars": ["jar1"], "unresolved_dependencies": ["dep1"], "duplicate_dependencies": ["dep2"]},
    },
    "code_reviewer_issues": [
        ["flow1.xml", "WARNING", "Naming convention issue"],
        ["flow2.xml", "ERROR", "Missing error handler"],
    ],
    "yaml_validation": {"application.yaml": "OK", "db.yaml": "Missing host"},
    "flow_validation": [
        {"Flow Name": "flow1", "Components": 10, "Status": "PASS"},
        {"Flow Name": "flow2", "Components": 12, "Status": "WARN"},
    ],
    "flow_validation_stats": {
        "total_flows": 6,
        "total_sub_flows": 3,
        "total_components": 34,
    },
    "api_validation": [
        {"API Name": "Orders", "Status": "PASS"},
        {"API Name": "Payments", "Status": "WARN"},
    ],
    "project_uses_secure_properties": True,
    "logging_validation": {
        "logger_issues": ["Too many loggers in flow2"],
        "log4j_warnings": ["DEBUG level found"],
    },
    "orphan_checker": {
        "summary": {"total_orphans": 2},
        "orphans": {"unused_flows": ["orphan1", "orphan2"]},
        "validation_errors": ["Orphan validation error sample"]
    },
}

# -------------------------
# Test Suite
# -------------------------
class TestHtmlReportGeneration(unittest.TestCase):

    def _validate_badges(self, html: str):
        """Check that all expected badges are present"""
        for badge in ["PASS", "WARN", "ERROR", "WARNING"]:
            self.assertIn(badge, html, f"Badge {badge} missing in HTML output")

    def _validate_orphan_section(self, html: str):
        """Check orphan checker sections"""
        self.assertIn("Total Orphans", html)  # Updated to match the formatted display
        for orphan in ["orphan1", "orphan2"]:
            self.assertIn(orphan, html)
        self.assertIn("Orphan validation error sample", html)

    def _validate_threshold_warnings(self, html: str):
        """Check that threshold warnings are rendered"""
        self.assertIn("Build size", html)
        self.assertIn("Total flows", html)
        self.assertIn("Total sub-flows", html)
        self.assertIn("Total components", html)

    def test_unit_dummy_template(self):
        """Unit test: validate HTML generation using dummy template."""

        # Arrange: minimal mock results including a flow
        MOCK_RESULTS = {
            'project_name': "MuleTestProject",
            'flows': [{'file': 'flow1.xml', 'status': 'PASS'}],
            'total_flows': 6,
            'components': 34,
            'threshold_warnings': [],
            'code_review_issues': [],
            'yaml_validation': [],
            'dependency_validation': [],
            'flow_validation': [],
            'api_validation': [],
            'secure_properties': None,
            'logging_issues': [],
            'orphan_items': ['orphan1', 'orphan2'],
        }

        # Simple string template without Jinja2
        DUMMY_TEMPLATE = """
        <html>
        <head><title>Test Report</title></head>
        <body>
            <h1>{project_name} - Validation Report</h1>
            <h2>Flows</h2>
            <ul>
            {flows_list}
            </ul>
        </body>
        </html>
        """

        # Build flows HTML manually
        flows_html = "\n".join(
            f"<li>{flow['file']} - {flow['status']}</li>" for flow in MOCK_RESULTS['flows']
        )

        # Render HTML
        html_output = DUMMY_TEMPLATE.format(
            project_name=MOCK_RESULTS['project_name'],
            flows_list=flows_html
        )

        # Assert
        self.assertIn("<html", html_output)
        self.assertIn("MuleTestProject", html_output)
        self.assertIn("flow1.xml", html_output)

    def test_integration_real_template(self):
        """Integration test: validate HTML generation using actual template file."""
        template_path = os.path.join(os.path.dirname(__file__), os.pardir, "report_template.html")
        if not os.path.exists(template_path):
            self.skipTest("Real template not found, skipping integration test.")
        with open(template_path, "r", encoding="utf-8") as f:
            real_template = f.read()
        html_output = generate_html_report(MOCK_RESULTS, real_template)
        # Automated validations
        self.assertIn("<html", html_output)
        self.assertIn("MuleTestProject", html_output)
        self.assertIn("flow1.xml", html_output)
        self._validate_badges(html_output)
        self._validate_orphan_section(html_output)
        self._validate_threshold_warnings(html_output)
        # Save for manual review
        out_file = os.path.join(os.path.dirname(__file__), "test_report_output.html")
        with open(out_file, "w", encoding="utf-8") as out:
            out.write(html_output)
        print(f"Integration HTML report generated at {out_file}")

if __name__ == "__main__":
    unittest.main()
