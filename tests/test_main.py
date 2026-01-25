import unittest
from unittest.mock import patch, MagicMock, mock_open
import sys
import os
import datetime

# Import the main function to be tested
from mule_validator.main import main

class TestMainOrchestration(unittest.TestCase):

    # Default arguments used in main.py's ArgumentParser
    DEFAULT_MAX_BUILD_SIZE_MB = 100
    DEFAULT_MAX_FLOWS = 100
    DEFAULT_MAX_SUB_FLOWS = 50
    DEFAULT_MAX_COMPONENTS = 500

    @patch('mule_validator.main.ensure_maven_and_build', MagicMock())
    @patch('mule_validator.main.get_current_git_branch', MagicMock(return_value="mock-branch"))
    @patch('mule_validator.main.MuleComprehensiveOrphanChecker')
    @patch('mule_validator.main.generate_html_report', MagicMock())
    @patch('mule_validator.main.review_all_files')
    @patch('mule_validator.main.validate_api_spec_and_flows')
    @patch('mule_validator.main.validate_flows_in_package')
    @patch('mule_validator.main.validate_all_projects')
    @patch('mule_validator.main.validate_files')
    @patch('mule_validator.main.validate_logging')
    @patch('logging.basicConfig')
    @patch('builtins.print')
    def test_main_orchestration_default_args(
        self, mock_print, mock_logging_basic_config, mock_validate_logging, mock_validate_files,
        mock_validate_all_projects, mock_validate_flows, mock_validate_api,
        mock_review_all, mock_orphan_checker
    ):
        """Test main() with default arguments"""
        test_package_path = '/path/to/package'
        
        # Mock return values for aggregation
        mock_review_all.return_value = (["code_issue1"], True)
        mock_validate_files.return_value = ["yaml_result1"]
        mock_validate_all_projects.return_value = {"pom.xml": {"all_dependencies": []}}
        mock_validate_flows.return_value = {
            "total_flows": 5,
            "total_sub_flows": 2,
            "total_components": 30,
            "invalid_flow_names": []
        }
        mock_validate_api.return_value = {"api_spec_found": True}
        mock_validate_logging.return_value = {"logger_issues": [], "log4j_warnings": []}
        
        # Mock orphan checker
        mock_orphan_instance = MagicMock()
        mock_orphan_instance.run.return_value = {
            "summary": {"orphan_flows_count": 0},
            "orphans": {},
            "used": {},
            "declared": {}
        }
        mock_orphan_checker.return_value = mock_orphan_instance

        # Patch datetime for predictable time values
        mock_now = datetime.datetime(2024, 1, 1, 12, 0, 0)
        mock_later = datetime.datetime(2024, 1, 1, 12, 0, 30)
        
        with patch.object(sys, 'argv', ['mule-validator', test_package_path]):
            with patch('mule_validator.main.datetime') as mock_datetime:
                mock_datetime.datetime.now.side_effect = [mock_now, mock_later]
                # FIXED: Catch SystemExit
                with self.assertRaises(SystemExit) as cm:
                    main()
                
                # Verify it exited with code 0 (success)
                self.assertEqual(cm.exception.code, 0)

        # Verify logging was configured
        mock_logging_basic_config.assert_called_once()

        # Assertions for validator calls
        mock_review_all.assert_called_with(test_package_path)
        mock_validate_files.assert_called_with(test_package_path, True)
        mock_validate_all_projects.assert_called_with(test_package_path)
        mock_validate_flows.assert_called_with(
            test_package_path,
            max_flows=self.DEFAULT_MAX_FLOWS,
            max_sub_flows=self.DEFAULT_MAX_SUB_FLOWS,
            max_components=self.DEFAULT_MAX_COMPONENTS
        )
        mock_validate_api.assert_called_with(test_package_path)
        mock_validate_logging.assert_called_with(test_package_path)


    @patch('mule_validator.main.ensure_maven_and_build', MagicMock())
    @patch('mule_validator.main.get_current_git_branch', MagicMock(return_value="custom-branch"))
    @patch('mule_validator.main.MuleComprehensiveOrphanChecker')
    @patch('builtins.open', new_callable=mock_open)
    @patch('mule_validator.main.generate_html_report')
    @patch('mule_validator.main.review_all_files')
    @patch('mule_validator.main.validate_api_spec_and_flows')
    @patch('mule_validator.main.validate_flows_in_package')
    @patch('mule_validator.main.validate_all_projects')
    @patch('mule_validator.main.validate_files')
    @patch('mule_validator.main.validate_logging')
    @patch('logging.basicConfig')
    @patch('builtins.print')
    def test_main_orchestration_custom_args_and_html_report(
        self, mock_print, mock_logging_basic_config, mock_validate_logging, mock_validate_files,
        mock_validate_all_projects, mock_validate_flows, mock_validate_api,
        mock_review_all, mock_html_report, mock_file_open, mock_orphan_checker
    ):
        """Test main() with custom arguments and HTML report generation"""
        custom_package_path = '/custom/package'
        report_file_path = '/tmp/report.html'

        cli_args = [
            'mule-validator',
            custom_package_path,
            '--report-file', report_file_path,
            '--max-flows', '150',
            '--max-sub-flows', '70',
            '--max-components', '600'
        ]

        # Mock return values
        mock_review_all.return_value = ([], False)
        mock_validate_files.return_value = []
        mock_validate_all_projects.return_value = {}
        mock_validate_flows.return_value = {
            "total_flows": 10,
            "total_sub_flows": 5,
            "total_components": 50,
            "invalid_flow_names": []
        }
        mock_validate_api.return_value = {}
        mock_validate_logging.return_value = {"logger_issues": [], "log4j_warnings": []}
        
        # Mock orphan checker
        mock_orphan_instance = MagicMock()
        mock_orphan_instance.run.return_value = {
            "summary": {"orphan_flows_count": 0},
            "orphans": {},
            "used": {},
            "declared": {}
        }
        mock_orphan_checker.return_value = mock_orphan_instance

        # Mock template reading and report writing
        template_content = "<html>{{git_branch_name}}</html>"
        mock_file_open.side_effect = [
            mock_open(read_data=template_content).return_value,  # For template
            mock_open().return_value  # For report file writing
        ]

        # Mock HTML report generation
        mock_html_report.return_value = "<html>custom-branch</html>"

        # Patch datetime for predictable time values
        mock_now = datetime.datetime(2024, 1, 1, 12, 0, 0)
        mock_later = datetime.datetime(2024, 1, 1, 12, 0, 30)

        with patch.object(sys, 'argv', cli_args):
            with patch('mule_validator.main.datetime') as mock_datetime:
                mock_datetime.datetime.now.side_effect = [mock_now, mock_later]
                # FIXED: Catch the SystemExit exception
                with self.assertRaises(SystemExit) as cm:
                    main()
                
                # Verify it exited with code 0 (success)
                self.assertEqual(cm.exception.code, 0)

        # Verify validate_all_projects was called with package path only
        mock_validate_all_projects.assert_called_with(custom_package_path)
        
        # Verify validate_flows was called with custom limits
        mock_validate_flows.assert_called_with(
            custom_package_path,
            max_flows=150,
            max_sub_flows=70,
            max_components=600
        )
        
        # Verify project_uses_secure_properties (False from mock_review_all) is passed
        mock_validate_files.assert_called_with(custom_package_path, False)

        # Assert HTML report generation was called
        mock_html_report.assert_called_once()
        
        # Check arguments of html_report call
        args_html_report, _ = mock_html_report.call_args
        self.assertIsInstance(args_html_report[0], dict)  # all_results
        self.assertEqual(args_html_report[1], template_content)  # template_content

        # Verify file operations
        expected_template_path = os.path.join(
            os.path.dirname(os.path.abspath(__file__).replace('tests', 'mule_validator')),
            'report_template.html'
        )
        
        # The template path will be constructed inside main(), so just verify open was called
        self.assertGreaterEqual(mock_file_open.call_count, 2)


    @patch('mule_validator.main.ensure_maven_and_build', MagicMock())
    @patch('mule_validator.main.get_current_git_branch', MagicMock(return_value="mock-branch"))
    @patch('mule_validator.main.generate_html_report', MagicMock())
    @patch('mule_validator.main.review_all_files', MagicMock(return_value=([], False)))
    @patch('mule_validator.main.validate_api_spec_and_flows', MagicMock())
    @patch('mule_validator.main.validate_flows_in_package', MagicMock())
    @patch('mule_validator.main.validate_all_projects', MagicMock())
    @patch('mule_validator.main.validate_files', MagicMock())
    @patch('mule_validator.main.validate_logging', MagicMock())
    @patch('logging.basicConfig', MagicMock())
    @patch('builtins.print')
    def test_arg_parser_missing_mandatory_argument(self, mock_print):
        """Test that main() exits when mandatory argument is missing"""
        with patch.object(sys, 'argv', ['mule-validator']):  # No package_folder_path
            with self.assertRaises(SystemExit) as e:
                main()
        
        # argparse exits with code 2 for argument errors
        self.assertEqual(e.exception.code, 2)


    @patch('mule_validator.main.ensure_maven_and_build', MagicMock(side_effect=SystemExit(1)))
    @patch('logging.basicConfig', MagicMock())
    @patch('builtins.print')
    def test_main_exits_if_maven_build_fails(self, mock_print):
        """Test that main() exits when Maven build fails"""
        with patch.object(sys, 'argv', ['mule-validator', '/dummy/path']):
            with self.assertRaises(SystemExit) as e:
                main()
            self.assertEqual(e.exception.code, 1)


if __name__ == '__main__':
    unittest.main()