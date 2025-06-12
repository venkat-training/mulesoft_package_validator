import unittest
from unittest.mock import patch, MagicMock, call
import sys
import argparse
import datetime # For mocking datetime
import os # For path joining if needed in assertions

# Import the main function to be tested
from mule_validator.main import main

class TestMainOrchestration(unittest.TestCase):

    # Default arguments used in main.py's ArgumentParser
    DEFAULT_MAX_BUILD_SIZE_MB = 100
    DEFAULT_MAX_FLOWS = 100
    DEFAULT_MAX_SUB_FLOWS = 50
    DEFAULT_MAX_COMPONENTS = 500

    @patch('mule_validator.main.ensure_maven_and_build', MagicMock()) # Assume build is fine
    @patch('mule_validator.main.get_current_git_branch', MagicMock(return_value="mock-branch"))
    @patch('mule_validator.main.generate_html_report', MagicMock())
    @patch('mule_validator.main.review_all_files')
    @patch('mule_validator.main.validate_api_spec_and_flows')
    @patch('mule_validator.main.validate_flows_in_package')
    @patch('mule_validator.main.validate_all_projects') # Corrected from validate_dependencies_and_size
    @patch('mule_validator.main.validate_files')
    @patch('mule_validator.main.validate_logging') # Added mock for validate_logging
    @patch('logging.basicConfig')
    @patch('builtins.print') # Mock print to suppress summary output during tests
    def test_main_orchestration_default_args(
        self, mock_print, mock_logging_basic_config, mock_validate_logging, mock_validate_files,
        mock_validate_all_projects, mock_validate_flows, mock_validate_api,
        mock_review_all, mock_html_report # Removed mock_get_branch as it's class-level patched
    ):
        # Simulate command line: main_script_name /path/to/package
        test_package_path = '/path/to/package'
        with patch.object(sys, 'argv', ['mule-validator', test_package_path]):
            main()

        mock_logging_basic_config.assert_called_once()

        # Mock return values for aggregation
        mock_review_all.return_value = (["code_issue1"], True) # issues, uses_secure_properties
        mock_validate_files.return_value = ["yaml_result1"]
        mock_validate_all_projects.return_value = {"pom.xml": {"all_dependencies": []}} # Simplified
        mock_validate_flows.return_value = {"total_counts": {"flows": 5}}
        mock_validate_api.return_value = {"api_spec_found": True}
        mock_validate_logging.return_value = {"logger_issues": [], "log4j_warnings": []}

        # Call main again to re-trigger with mocks having return values for all_results check
        with patch.object(sys, 'argv', ['mule-validator', test_package_path]):
             # Patch datetime for predictable time values
            mock_now = datetime.datetime(2024, 1, 1, 12, 0, 0)
            mock_later = datetime.datetime(2024, 1, 1, 12, 0, 30)
            with patch('datetime.datetime') as mock_datetime:
                mock_datetime.now.side_effect = [mock_now, mock_later] # First call for start, second for end
                main()


        # Assertions for validator calls
        mock_review_all.assert_called_with(test_package_path)
        mock_validate_files.assert_called_with(test_package_path, True) # project_uses_secure_properties is True
        mock_validate_all_projects.assert_called_with(test_package_path) # build_folder_path defaults to package_folder_path

        mock_validate_flows.assert_called_with(
            test_package_path,
            max_flows=self.DEFAULT_MAX_FLOWS,
            max_sub_flows=self.DEFAULT_MAX_SUB_FLOWS,
            max_components=self.DEFAULT_MAX_COMPONENTS
        )
        mock_validate_api.assert_called_with(test_package_path)
        mock_validate_logging.assert_called_with(test_package_path)

        # Assert that ensure_maven_and_build and get_current_git_branch were called
        # These are class-level patched with MagicMock(), so they are called.
        self.assertTrue(main.ensure_maven_and_build.called)
        self.assertTrue(main.get_current_git_branch.called)

        # Check the aggregated results passed to the (mocked) HTML reporter if a report file was specified.
        # For this test, no --report-file, so generate_html_report is not called.
        mock_html_report.assert_not_called()

        # Check the print call for the summary
        # The last call to print will be the summary.
        # We need to find the call that prints the all_results dictionary.
        # This is a bit fragile if print is used for other things extensively.
        # A more robust way would be to capture the argument to a specific reporter function if console report was separate.

        # Find the print call that contains the all_results dictionary
        printed_summary_found = False
        for print_call in mock_print.call_args_list:
            args, kwargs = print_call
            if args and isinstance(args[0], str) and "Summary of all validation results:" in args[0]:
                # The next arg should be the dictionary
                if len(args) > 1 and isinstance(args[1], dict):
                    printed_all_results = args[1]
                    self.assertEqual(printed_all_results['code_reviewer_issues'], ["code_issue1"])
                    self.assertTrue(printed_all_results['project_uses_secure_properties'])
                    self.assertEqual(printed_all_results['yaml_validation'], ["yaml_result1"])
                    self.assertEqual(printed_all_results['dependency_validation'], {"pom.xml": {"all_dependencies": []}})
                    self.assertEqual(printed_all_results['flow_validation'], {"total_counts": {"flows": 5}})
                    self.assertEqual(printed_all_results['api_validation'], {"api_spec_found": True})
                    self.assertEqual(printed_all_results['logging_validation'], {"logger_issues": [], "log4j_warnings": []})
                    self.assertEqual(printed_all_results['git_branch_name'], "mock-branch")
                    self.assertEqual(printed_all_results['report_start_time'], "2024-01-01 12:00:00")
                    self.assertEqual(printed_all_results['report_end_time'], "2024-01-01 12:00:30")
                    self.assertEqual(printed_all_results['report_duration'], str(mock_later - mock_now))
                    printed_summary_found = True
                    break
        self.assertTrue(printed_summary_found, "Summary print call not found or structure incorrect")


    @patch('mule_validator.main.ensure_maven_and_build', MagicMock())
    @patch('mule_validator.main.get_current_git_branch', MagicMock(return_value="custom-branch"))
    @patch('builtins.open', new_callable=mock_open) # For report file and template
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
        mock_review_all, mock_html_report, mock_file_open # mock_get_branch is class-level
    ):
        custom_package_path = '/custom/package'
        custom_build_path = '/custom/build'
        report_file_path = '/tmp/report.html'

        cli_args = [
            'mule-validator',
            custom_package_path,
            '--report-file', report_file_path,
            '--build-folder-path', custom_build_path,
            '--max-flows', '150',
            '--max-sub-flows', '70',
            '--max-components', '600'
            # max-build-size-mb is not directly used by validate_all_projects
        ]

        # Mock return values
        mock_review_all.return_value = ([], False) # issues, uses_secure_properties
        # ... other mocks can return default MagicMock() or specific values if needed for assertions

        # Mock template reading
        mock_file_open.side_effect = [
            mock_open(read_data="<html>{{git_branch_name}}</html>").return_value, # For template
            mock_open().return_value # For report file writing
        ]

        with patch.object(sys, 'argv', cli_args):
            # Patch datetime for predictable time values
            mock_now = datetime.datetime(2024, 1, 1, 12, 0, 0)
            mock_later = datetime.datetime(2024, 1, 1, 12, 0, 30)
            with patch('datetime.datetime') as mock_datetime:
                mock_datetime.now.side_effect = [mock_now, mock_later]
                main()

        mock_validate_all_projects.assert_called_with(custom_package_path) # build_folder_path is not passed to validate_all_projects
        mock_validate_flows.assert_called_with(
            custom_package_path,
            max_flows=150,
            max_sub_flows=70,
            max_components=600
        )
        # Check that project_uses_secure_properties (False from mock_review_all) is passed to validate_files
        mock_validate_files.assert_called_with(custom_package_path, False)


        # Assert HTML report generation was called
        mock_html_report.assert_called_once()
        # Check some args of html_report call (the all_results dict)
        args_html_report, _ = mock_html_report.call_args
        self.assertIsInstance(args_html_report[0], dict) # all_results
        self.assertEqual(args_html_report[0]['git_branch_name'], "custom-branch")
        self.assertEqual(args_html_report[0]['project_uses_secure_properties'], False)
        self.assertEqual(args_html_report[1], "<html>{{git_branch_name}}</html>") # template_content

        # Check file operations for report
        expected_template_path = 'mule_validator/report_template.html'
        # mock_file_open.assert_any_call(expected_template_path, 'r') # This is a bit tricky with multiple open calls
        # Instead, check the path used in the first call to open
        self.assertEqual(mock_file_open.call_args_list[0][0][0], expected_template_path)
        self.assertEqual(mock_file_open.call_args_list[0][1], 'r') # Mode 'r'

        self.assertEqual(mock_file_open.call_args_list[1][0][0], report_file_path)
        self.assertEqual(mock_file_open.call_args_list[1][1], 'w') # Mode 'w'

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
    @patch('builtins.print') # Mock print
    def test_arg_parser_missing_mandatory_argument(self, mock_print): # Renamed capsys to mock_print
        with patch.object(sys, 'argv', ['mule-validator']): # No package_folder_path
            with self.assertRaises(SystemExit) as e:
                main()
        self.assertEqual(e.exception.code, 2)

        # Check if argparse error message was printed (approximate check)
        # This relies on argparse printing to stderr, which print doesn't capture by default.
        # For robust stderr checking, you might need to redirect sys.stderr or use a more specific test for argparse.
        # However, SystemExit code 2 is a strong indicator from argparse.
        # We can check the mock_print calls for error messages that argparse might route there.
        error_message_found = False
        for call_args in mock_print.call_args_list:
            if "the following arguments are required: package_folder_path" in str(call_args):
                error_message_found = True
                break
        # Note: argparse prints to stderr. If main redirects stderr or if test framework captures it,
        # this check might need adjustment. For now, SystemExit is the primary check.
        # self.assertTrue(error_message_found, "Argparse error message for missing argument not found in print output.")
        # This assertion is commented out because argparse prints to stderr, not stdout (mocked by mock_print).

    @patch('mule_validator.main.ensure_maven_and_build', MagicMock(side_effect=SystemExit(1)))
    @patch('logging.basicConfig', MagicMock())
    @patch('builtins.print')
    def test_main_exits_if_maven_build_fails(self, mock_print):
        with patch.object(sys, 'argv', ['mule-validator', '/dummy/path']):
            with self.assertRaises(SystemExit) as e:
                main()
            self.assertEqual(e.exception.code, 1)
            # ensure_maven_and_build internally prints messages before exiting.

if __name__ == '__main__':
    unittest.main()
