import unittest
from unittest.mock import patch, mock_open, MagicMock
import os
from lxml import etree

# Assuming logs_reviewer.py is in mule_validator directory, and tests is a sibling to mule_validator
import sys
# Add the parent directory of 'mule_validator' to the Python path
# This allows importing from mule_validator as if running from the project root
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

from mule_validator import logs_reviewer

class TestLogsReviewer(unittest.TestCase):

    def _create_mock_xml_tree(self, xml_string):
        """Helper to create a mock etree object from an XML string."""
        try:
            return etree.fromstring(xml_string.encode('utf-8'))
        except etree.XMLSyntaxError as e:
            # For tests that expect parse errors, this helps identify if the XML is truly malformed
            print(f"XML Syntax Error in test data: {e}")
            raise

    @patch('lxml.etree.parse')
    def test_find_logger_issues_no_loggers(self, mock_parse):
        xml_content = """
        <mule xmlns="http://www.mulesoft.org/schema/mule/core">
            <flow name="flowWithNoLoggers">
                <set-payload value="test"/>
            </flow>
        </mule>
        """
        mock_tree = MagicMock()
        mock_tree.getroot.return_value = self._create_mock_xml_tree(xml_content)
        mock_parse.return_value = mock_tree

        issues = logs_reviewer.find_logger_issues("dummy/path/no_loggers.xml")
        self.assertEqual(len(issues), 0)

    @patch('lxml.etree.parse')
    def test_find_logger_issues_valid_loggers(self, mock_parse):
        xml_content = """
        <mule xmlns="http://www.mulesoft.org/schema/mule/core">
            <flow name="flowWithValidLoggers">
                <logger level="INFO" message="Start"/>
                <logger level="INFO" message="End"/>
            </flow>
        </mule>
        """
        mock_tree = MagicMock()
        mock_tree.getroot.return_value = self._create_mock_xml_tree(xml_content)
        mock_parse.return_value = mock_tree

        issues = logs_reviewer.find_logger_issues("dummy/path/valid_loggers.xml")
        self.assertEqual(len(issues), 0) # No issues expected

    @patch('lxml.etree.parse')
    def test_find_logger_issues_too_many_loggers(self, mock_parse):
        xml_content = """
        <mule xmlns="http://www.mulesoft.org/schema/mule/core">
            <flow name="flowWithTooManyLoggers">
                <logger level="INFO" message="Log 1"/>
                <logger level="INFO" message="Log 2"/>
                <logger level="INFO" message="Log 3"/>
                <logger level="INFO" message="Log 4"/>
                <logger level="INFO" message="Log 5"/>
            </flow>
        </mule>
        """
        mock_tree = MagicMock()
        mock_tree.getroot.return_value = self._create_mock_xml_tree(xml_content)
        mock_parse.return_value = mock_tree

        issues = logs_reviewer.find_logger_issues("dummy/path/too_many_loggers.xml")
        self.assertEqual(len(issues), 1)
        issue = issues[0]
        self.assertEqual(issue["flow"], "flowWithTooManyLoggers")
        self.assertTrue(issue["has_too_many_loggers"])
        self.assertEqual(issue["logger_count"], 5)

    @patch('lxml.etree.parse')
    def test_find_logger_issues_debug_logger(self, mock_parse):
        xml_content = """
        <mule xmlns="http://www.mulesoft.org/schema/mule/core">
            <flow name="flowWithDebugLogger">
                <logger level="DEBUG" message="Debugging info"/>
            </flow>
        </mule>
        """
        mock_tree = MagicMock()
        mock_tree.getroot.return_value = self._create_mock_xml_tree(xml_content)
        mock_parse.return_value = mock_tree

        issues = logs_reviewer.find_logger_issues("dummy/path/debug_logger.xml")
        self.assertEqual(len(issues), 1)
        issue = issues[0]
        self.assertEqual(issue["flow"], "flowWithDebugLogger")
        self.assertTrue(issue["has_debug"])
        self.assertEqual(issue["debug_count"], 1)

    @patch('lxml.etree.parse')
    def test_find_logger_issues_error_logger_outside_handler(self, mock_parse):
        xml_content = """
        <mule xmlns="http://www.mulesoft.org/schema/mule/core">
            <flow name="flowWithErrorLoggerOutsideHandler">
                <logger level="ERROR" message="An error occurred"/>
            </flow>
        </mule>
        """
        mock_tree = MagicMock()
        mock_tree.getroot.return_value = self._create_mock_xml_tree(xml_content)
        mock_parse.return_value = mock_tree

        issues = logs_reviewer.find_logger_issues("dummy/path/error_logger_outside.xml")
        self.assertEqual(len(issues), 1)
        issue = issues[0]
        self.assertEqual(issue["flow"], "flowWithErrorLoggerOutsideHandler")
        self.assertTrue(issue["error_outside_exception"])
        self.assertEqual(issue["error_count"], 1)

    @patch('lxml.etree.parse')
    def test_find_logger_issues_error_logger_inside_handler(self, mock_parse):
        xml_content = """
        <mule xmlns="http://www.mulesoft.org/schema/mule/core">
            <flow name="flowWithErrorLoggerInsideHandler">
                <try>
                    <set-payload value="attempt something"/>
                    <error-handler>
                        <on-error-propagate type="ANY">
                            <logger level="ERROR" message="Error caught and logged"/>
                        </on-error-propagate>
                    </error-handler>
                </try>
            </flow>
        </mule>
        """
        # The current logic ` "errorHandler" not in flow.tag ` is a bit simplistic.
        # For this to pass as "not an issue", the logger needs to be directly inside a flow/sub-flow
        # whose tag contains "errorHandler". This mock XML won't satisfy that.
        # A more robust check would inspect parent tags.
        # Given current implementation, this will be flagged as error_outside_exception.
        # We will test the current behavior.
        # If the logic of logs_reviewer.py is improved, this test will need adjustment.

        mock_tree = MagicMock()
        mock_tree.getroot.return_value = self._create_mock_xml_tree(xml_content)
        mock_parse.return_value = mock_tree

        issues = logs_reviewer.find_logger_issues("dummy/path/error_logger_inside.xml")
        # Based on current simple logic: `if issue["error_outside_exception"]: issues.append(issue)`
        # and ` "errorHandler" not in flow.tag `
        # The 'flow' tag is "flow", which does not contain "errorHandler".
        # So, this will be flagged.
        self.assertEqual(len(issues), 1)
        issue = issues[0]
        self.assertEqual(issue["flow"], "flowWithErrorLoggerInsideHandler")
        self.assertTrue(issue["error_outside_exception"]) # This is current behavior
        self.assertEqual(issue["error_count"], 1)


    @patch('lxml.etree.parse')
    def test_find_logger_issues_error_logger_inside_handler_direct_child_of_error_handler_flow(self, mock_parse):
        # This test simulates a scenario where the logger is a direct child of an error-handler flow.
        # This scenario is NOT how Mule error handlers are structured. Error handlers contain scopes,
        # and loggers would be within those scopes, or within flows/sub-flows called by those scopes.
        # The current check ` "errorHandler" not in flow.tag ` is on the <flow> or <sub-flow> element itself.
        # A flow named e.g. "myErrorHandlerFlow" would not be caught by this.
        # This test highlights the limitation of the current check.
        xml_content = """
        <mule xmlns="http://www.mulesoft.org/schema/mule/core">
            <flow name="customErrorHandlerFlow">
                <!-- If this flow IS an error handler, its name might reflect it, but tag is 'flow' -->
                <logger level="ERROR" message="Error in custom error flow"/>
            </flow>
        </mule>
        """
        mock_tree = MagicMock()
        mock_tree.getroot.return_value = self._create_mock_xml_tree(xml_content)
        mock_parse.return_value = mock_tree

        issues = logs_reviewer.find_logger_issues("dummy/path/custom_error_flow.xml")
        self.assertEqual(len(issues), 1) # Will be flagged due to simple check
        self.assertTrue(issues[0]["error_outside_exception"])


    @patch('lxml.etree.parse')
    def test_find_logger_issues_malformed_xml(self, mock_parse):
        mock_parse.side_effect = etree.XMLSyntaxError("Malformed XML", 0, 0, 0)
        issues = logs_reviewer.find_logger_issues("dummy/path/malformed.xml")
        self.assertEqual(len(issues), 0) # Should handle error gracefully and return no issues


    @patch('lxml.etree.parse')
    def test_find_logger_issues_sub_flow(self, mock_parse):
        xml_content = """
        <mule xmlns="http://www.mulesoft.org/schema/mule/core">
            <sub-flow name="subFlowWithDebug">
                <logger level="DEBUG" message="Debugging sub-flow"/>
            </sub-flow>
        </mule>
        """
        mock_tree = MagicMock()
        mock_tree.getroot.return_value = self._create_mock_xml_tree(xml_content)
        mock_parse.return_value = mock_tree

        issues = logs_reviewer.find_logger_issues("dummy/path/subflow_debug.xml")
        self.assertEqual(len(issues), 1)
        issue = issues[0]
        self.assertEqual(issue["flow"], "subFlowWithDebug") # Name of the sub-flow
        self.assertTrue(issue["has_debug"])

    @patch('os.walk')
    @patch('mule_validator.logs_reviewer.find_logger_issues') # Patch find_logger_issues
    def test_find_logger_issues_in_project(self, mock_find_logger_issues, mock_os_walk):
        # Configure os.walk mock
        mock_os_walk.return_value = [
            ('/project/src/main/mule', [], ['file1.xml', 'file2.xml']),
            ('/project/src/main/mule/subfolder', [], ['file3.xml']),
        ]

        # Configure find_logger_issues mock to return different results for different files
        def find_issues_side_effect(file_path):
            if file_path == os.path.join('/project/src/main/mule', 'file1.xml'):
                return [{"file": "file1.xml", "flow": "flow1", "has_debug": True, "logger_count":1, "debug_count":1, "error_count":0, "has_too_many_loggers":False, "error_outside_exception":False}]
            elif file_path == os.path.join('/project/src/main/mule', 'file2.xml'):
                return [] # No issues
            elif file_path == os.path.join('/project/src/main/mule/subfolder', 'file3.xml'):
                return [{"file": "file3.xml", "flow": "flow3", "has_too_many_loggers": True, "logger_count":5, "debug_count":0, "error_count":0, "has_debug":False, "error_outside_exception":False}]
            return []

        mock_find_logger_issues.side_effect = find_issues_side_effect

        project_path = "/project"
        all_project_issues = logs_reviewer.find_logger_issues_in_project(project_path)

        self.assertEqual(len(all_project_issues), 2)
        self.assertEqual(mock_find_logger_issues.call_count, 3)
        # Check that specific issues are present
        self.assertTrue(any(issue["flow"] == "flow1" and issue["has_debug"] for issue in all_project_issues))
        self.assertTrue(any(issue["flow"] == "flow3" and issue["has_too_many_loggers"] for issue in all_project_issues))


    # Tests for analyze_log4j_config
    @patch('lxml.etree.parse')
    @patch('os.path.isfile')
    def test_analyze_log4j_config_debug_level(self, mock_isfile, mock_parse):
        mock_isfile.return_value = True
        xml_content = """<Configuration><Loggers><Root level="DEBUG"/></Loggers></Configuration>"""
        mock_tree = MagicMock()
        mock_tree.getroot.return_value = self._create_mock_xml_tree(xml_content) # Use actual root from string
        # Mock find to simulate finding the Root logger element
        root_logger_element = self._create_mock_xml_tree(xml_content).find('.//Root') # Get the element
        mock_tree.find.return_value = root_logger_element
        mock_parse.return_value = mock_tree

        warnings = logs_reviewer.analyze_log4j_config("/dummy_project")
        self.assertEqual(len(warnings), 1)
        self.assertIn("Root logger set to verbose level: DEBUG", warnings[0])

    @patch('lxml.etree.parse')
    @patch('os.path.isfile')
    def test_analyze_log4j_config_trace_level(self, mock_isfile, mock_parse):
        mock_isfile.return_value = True
        xml_content = """<Configuration><Loggers><Root level="TRACE"/></Loggers></Configuration>"""
        mock_tree = MagicMock(); mock_tree.getroot.return_value = self._create_mock_xml_tree(xml_content)
        mock_tree.find.return_value = self._create_mock_xml_tree(xml_content).find('.//Root')
        mock_parse.return_value = mock_tree
        warnings = logs_reviewer.analyze_log4j_config("/dummy_project")
        self.assertEqual(len(warnings), 1)
        self.assertIn("Root logger set to verbose level: TRACE", warnings[0])

    @patch('lxml.etree.parse')
    @patch('os.path.isfile')
    def test_analyze_log4j_config_info_level(self, mock_isfile, mock_parse):
        mock_isfile.return_value = True
        xml_content = """<Configuration><Loggers><Root level="INFO"/></Loggers></Configuration>"""
        mock_tree = MagicMock(); mock_tree.getroot.return_value = self._create_mock_xml_tree(xml_content)
        mock_tree.find.return_value = self._create_mock_xml_tree(xml_content).find('.//Root')
        mock_parse.return_value = mock_tree
        warnings = logs_reviewer.analyze_log4j_config("/dummy_project")
        self.assertEqual(len(warnings), 1)
        self.assertIn("Root logger set to verbose level: INFO", warnings[0])

    @patch('lxml.etree.parse')
    @patch('os.path.isfile')
    def test_analyze_log4j_config_warn_level(self, mock_isfile, mock_parse):
        mock_isfile.return_value = True
        xml_content = """<Configuration><Loggers><Root level="WARN"/></Loggers></Configuration>"""
        mock_tree = MagicMock(); mock_tree.getroot.return_value = self._create_mock_xml_tree(xml_content)
        mock_tree.find.return_value = self._create_mock_xml_tree(xml_content).find('.//Root')
        mock_parse.return_value = mock_tree
        warnings = logs_reviewer.analyze_log4j_config("/dummy_project")
        self.assertEqual(len(warnings), 0) # No warning for WARN

    @patch('lxml.etree.parse')
    @patch('os.path.isfile')
    def test_analyze_log4j_config_capital_level_attr(self, mock_isfile, mock_parse):
        mock_isfile.return_value = True
        xml_content = """<Configuration><Loggers><Root Level="DEBUG"/></Loggers></Configuration>""" # Capital 'L'
        mock_tree = MagicMock(); mock_tree.getroot.return_value = self._create_mock_xml_tree(xml_content)
        mock_tree.find.return_value = self._create_mock_xml_tree(xml_content).find('.//Root')
        mock_parse.return_value = mock_tree
        warnings = logs_reviewer.analyze_log4j_config("/dummy_project")
        self.assertEqual(len(warnings), 1)
        self.assertIn("Root logger set to verbose level: DEBUG", warnings[0])

    @patch('lxml.etree.parse')
    @patch('os.path.isfile')
    def test_analyze_log4j_config_no_root_logger(self, mock_isfile, mock_parse):
        mock_isfile.return_value = True
        xml_content = """<Configuration><Loggers/></Configuration>""" # No Root logger
        mock_tree = MagicMock(); mock_tree.getroot.return_value = self._create_mock_xml_tree(xml_content)
        mock_tree.find.return_value = None # Simulate Root logger not found
        mock_parse.return_value = mock_tree
        warnings = logs_reviewer.analyze_log4j_config("/dummy_project")
        self.assertEqual(len(warnings), 0) # No warning if no root logger

    @patch('lxml.etree.parse')
    @patch('os.path.isfile')
    def test_analyze_log4j_config_malformed_xml(self, mock_isfile, mock_parse):
        mock_isfile.return_value = True
        mock_parse.side_effect = etree.XMLSyntaxError("Malformed log4j2", 0,0,0)
        warnings = logs_reviewer.analyze_log4j_config("/dummy_project")
        self.assertEqual(len(warnings), 1)
        self.assertIn("Error reading log4j2.xml", warnings[0])

    @patch('os.path.isfile')
    def test_analyze_log4j_config_file_missing(self, mock_isfile):
        mock_isfile.return_value = False # log4j2.xml does not exist
        warnings = logs_reviewer.analyze_log4j_config("/dummy_project")
        self.assertEqual(len(warnings), 1)
        self.assertIn("Log4j configuration file not found", warnings[0])

    # Tests for validate_logging
    @patch('mule_validator.logs_reviewer.find_logger_issues_in_project')
    @patch('mule_validator.logs_reviewer.analyze_log4j_config')
    def test_validate_logging(self, mock_analyze_log4j, mock_find_logger_issues_project):
        mock_issues = [{"file": "file1.xml", "flow": "flow1", "has_debug": True}]
        mock_warnings = ["Root logger set to verbose level: DEBUG"]

        mock_find_logger_issues_project.return_value = mock_issues
        mock_analyze_log4j.return_value = mock_warnings

        expected_results = {
            "logger_issues": mock_issues,
            "log4j_warnings": mock_warnings
        }

        results = logs_reviewer.validate_logging("/dummy_project")

        self.assertEqual(results, expected_results)
        mock_find_logger_issues_project.assert_called_once_with("/dummy_project")
        mock_analyze_log4j.assert_called_once_with("/dummy_project")

if __name__ == '__main__':
    unittest.main()
