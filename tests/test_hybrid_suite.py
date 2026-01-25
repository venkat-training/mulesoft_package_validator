"""
Hybrid Test Suite for MuleSoft Validation

- Combines HTML report generation tests and API validator tests
- Fully mocked for isolated testing
- Supports integration test with real template if available

Run with:
    python -m unittest tests/test_hybrid_suite.py
"""

import os
import sys
import unittest
from unittest.mock import patch, MagicMock
import xml.etree.ElementTree as ET

# Add repo root to sys.path
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from mule_validator import html_reporter, api_validator

# -------------------------
# Constants for testing
# -------------------------
APIKIT_NAMESPACE_URIS = [
    "http://www.mulesoft.org/schema/mule/apikit",
    "http://www.mulesoft.org/schema/mule/mule-apikit"
]

SRC_MAIN_MULE_PATH_NAME = "src/main/mule"

# -------------------------
# Dummy HTML template
# -------------------------
DUMMY_TEMPLATE = """
<html>
<head><title>Test Report</title></head>
<body>
<h1>{{ project_name }} - Validation Report</h1>
<p>Status: {{ status }}</p>

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
# Mock results
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
# Hybrid Test Suite
# -------------------------
class TestHybridSuite(unittest.TestCase):

    # ---------------------
    # HTML Report Tests
    # ---------------------
    def _validate_badges(self, html: str):
        """Validate that status badges are present in HTML"""
        html_lower = html.lower()
        badge_found = False
        for badge in ["pass", "warn", "error", "warning"]:
            if badge in html_lower:
                badge_found = True
                break
        self.assertTrue(badge_found, "No status badges found in HTML output")

    def _validate_orphan_section(self, html: str):
        """Validate orphan checker section in HTML"""
        self.assertIn("Total Orphans", html, "Total Orphans not found")
        for orphan in ["orphan1", "orphan2"]:
            self.assertIn(orphan, html, f"Orphan '{orphan}' not found")
        self.assertIn("Orphan validation error sample", html, "Validation error not found")

    def _validate_threshold_warnings(self, html: str):
        """Validate threshold warnings section exists and contains build size warning"""
        self.assertIn("Threshold Warnings", html, "Threshold Warnings section not found")
        # Check for build size warning (generated automatically from dependency_validation)
        self.assertIn("Build size", html, "Build size warning not found")

    def test_html_report_dummy_template(self):
        """Test HTML generation with dummy template"""
        html_output = html_reporter.generate_html_report(MOCK_RESULTS, DUMMY_TEMPLATE)
        
        # Basic structure checks
        self.assertIn("<html", html_output)
        self.assertIn("MuleTestProject", html_output)
        
        # Check for data from various sections
        self.assertIn("flow1.xml", html_output)
        self.assertIn("db.yaml", html_output)
        self.assertIn("Orders", html_output)
        
        # Validate sections
        self._validate_badges(html_output)
        self._validate_orphan_section(html_output)
        self._validate_threshold_warnings(html_output)
        
        # Verify template variables were NOT replaced (because they're not in the function)
        self.assertNotIn("{{ project_name }}", html_output)
        self.assertNotIn("{{ status }}", html_output)

    def test_html_report_real_template(self):
        """Integration test with real template file"""
        template_path = os.path.join(os.path.dirname(__file__), os.pardir, "report_template.html")
        if not os.path.exists(template_path):
            self.skipTest("Real template not found, skipping integration test.")
        
        with open(template_path, "r", encoding="utf-8") as f:
            real_template = f.read()
        
        html_output = html_reporter.generate_html_report(MOCK_RESULTS, real_template)
        
        # Basic checks
        self.assertIn("<html", html_output)
        self.assertIn("MuleTestProject", html_output)
        
        # Validate sections
        self._validate_badges(html_output)
        self._validate_orphan_section(html_output)
        self._validate_threshold_warnings(html_output)

    def test_html_report_no_threshold_warnings(self):
        """Test when no threshold warnings are present"""
        results_no_warnings = MOCK_RESULTS.copy()
        results_no_warnings['dependency_validation'] = {"build_size_mb": 50}  # Below threshold
        results_no_warnings.pop('threshold_warnings', None)
        
        html_output = html_reporter.generate_html_report(results_no_warnings, DUMMY_TEMPLATE)
        
        self.assertIn("No threshold warnings", html_output)

    def test_html_report_explicit_threshold_warnings(self):
        """Test with explicit threshold warnings provided"""
        results_with_warnings = MOCK_RESULTS.copy()
        results_with_warnings['threshold_warnings'] = [
            "Flow count exceeds limit",
            "Component count too high"
        ]
        
        html_output = html_reporter.generate_html_report(results_with_warnings, DUMMY_TEMPLATE)
        
        self.assertIn("Flow count exceeds limit", html_output)
        self.assertIn("Component count too high", html_output)

    # ---------------------
    # API Validator Tests
    # ---------------------
    def _mock_pom_tree(self, has_raml=True):
        if has_raml:
            content = f"""
            <project xmlns="http://maven.apache.org/POM/4.0.0">
                <dependencies>
                    <dependency>
                        <groupId>com.example</groupId>
                        <artifactId>my-api-spec</artifactId>
                        <version>1.0.0</version>
                        <classifier>raml</classifier>
                        <type>zip</type>
                    </dependency>
                </dependencies>
            </project>
            """
        else:
            content = "<project xmlns='http://maven.apache.org/POM/4.0.0'><dependencies></dependencies></project>"
        return ET.fromstring(content)

    def _mock_mule_tree(self, has_router=True, ns_index=0):
        ns_uri = APIKIT_NAMESPACE_URIS[ns_index]
        if has_router:
            mule_content = f"""
            <mule xmlns="http://www.mulesoft.org/schema/mule/core"
                  xmlns:apikit="{ns_uri}">
                <flow name="api-main">
                    <apikit:router config-ref="api-config"/>
                </flow>
                <apikit:config name="api-config" raml="api.raml"/>
            </mule>
            """
        else:
            mule_content = """
            <mule xmlns="http://www.mulesoft.org/schema/mule/core">
                <flow name="some-flow">
                    <logger message="Hello"/>
                </flow>
            </mule>
            """
        return ET.fromstring(mule_content)

    @patch('os.path.isfile')
    @patch('xml.etree.ElementTree.parse')
    @patch('os.walk')
    @patch('os.path.basename')
    @patch('os.path.abspath')
    def test_api_validator_all_conditions_met(self, mock_abspath, mock_basename, mock_os_walk, mock_et_parse, mock_isfile):
        """Test API validator when all conditions are met"""
        project_path = "/dummy/project/test"
        mock_abspath.return_value = project_path
        mock_basename.return_value = "test"

        mock_isfile.side_effect = lambda path: True
        mock_pom_tree = MagicMock()
        mock_pom_tree.getroot.return_value = self._mock_pom_tree()
        mock_mule_tree = MagicMock()
        mock_mule_tree.getroot.return_value = self._mock_mule_tree()

        def et_parse_side_effect(path):
            if path.endswith("pom.xml"):
                return mock_pom_tree
            return mock_mule_tree
        mock_et_parse.side_effect = et_parse_side_effect

        mock_os_walk.return_value = [(os.path.join(project_path, "target"), [], ["my-api-spec-1.0.0-raml.zip"])]

        results = api_validator.validate_api_spec_and_flows(project_path)

        self.assertTrue(results['api_spec_zip_found'])
        self.assertTrue(results['apikit_router_found'])
        self.assertEqual(results['apikit_router_file'], "test.xml")
        self.assertEqual(results['api_spec_dependency'], "com.example:my-api-spec:1.0.0:raml:zip")
        self.assertEqual(len(results['notes']), 0)

    @patch('os.path.isfile')
    @patch('xml.etree.ElementTree.parse')
    def test_api_validator_missing_raml_dependency(self, mock_et_parse, mock_isfile):
        """Test API validator when RAML dependency is missing"""
        project_path = "/dummy/project/test"
        
        mock_isfile.return_value = True
        mock_pom_tree = MagicMock()
        mock_pom_tree.getroot.return_value = self._mock_pom_tree(has_raml=False)
        mock_et_parse.return_value = mock_pom_tree

        results = api_validator.validate_api_spec_and_flows(project_path)

        self.assertIsNone(results['api_spec_dependency'])
        self.assertFalse(results['api_spec_zip_found'])
        self.assertGreater(len(results['notes']), 0)

    @patch('os.path.isfile')
    @patch('xml.etree.ElementTree.parse')
    @patch('os.walk')
    @patch('os.path.basename')
    @patch('os.path.abspath')
    def test_api_validator_missing_apikit_router(self, mock_abspath, mock_basename, mock_os_walk, mock_et_parse, mock_isfile):
        """Test API validator when APIkit router is missing"""
        project_path = "/dummy/project/test"
        mock_abspath.return_value = project_path
        mock_basename.return_value = "test"

        mock_isfile.side_effect = lambda path: True
        
        mock_pom_tree = MagicMock()
        mock_pom_tree.getroot.return_value = self._mock_pom_tree(has_raml=True)
        
        mock_mule_tree = MagicMock()
        mock_mule_tree.getroot.return_value = self._mock_mule_tree(has_router=False)

        def et_parse_side_effect(path):
            if path.endswith("pom.xml"):
                return mock_pom_tree
            return mock_mule_tree
        mock_et_parse.side_effect = et_parse_side_effect

        mock_os_walk.return_value = [(os.path.join(project_path, "target"), [], ["my-api-spec-1.0.0-raml.zip"])]

        results = api_validator.validate_api_spec_and_flows(project_path)

        self.assertTrue(results['api_spec_zip_found'])
        self.assertFalse(results['apikit_router_found'])
        self.assertGreater(len(results['notes']), 0)


if __name__ == "__main__":
    unittest.main()