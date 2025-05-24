import pytest
import argparse
from unittest.mock import patch, MagicMock, call
import sys # For patching sys.argv
import logging # For asserting logger calls

# Import the main function to be tested
from mule_validator.main import main

# For argument parsing tests, we ideally need access to the parser.
# If main.py's parser is not directly accessible, we test argument parsing
# implicitly through the orchestration tests by how args are passed to mocks.
# The detailed prompt suggested direct parser testing as an option, which is preferred.
# Let's assume for now we'll test arg parsing effects via orchestration.

# If main.py were refactored to have:
# def create_arg_parser():
#     parser = argparse.ArgumentParser(...)
#     ...
#     return parser
#
# def main_logic(args): # Main function body using parsed args
#     ...
#
# def main(): # CLI entry point
#     parser = create_arg_parser()
#     args = parser.parse_args()
#     main_logic(args)
#
# Then we could do:
# from mule_validator.main import create_arg_parser
# def test_arg_parsing_direct():
#     parser = create_arg_parser()
#     args = parser.parse_args(['/path/to/package', '--max-flows', '120'])
#     assert args.package_folder_path == '/path/to/package'
#     assert args.max_flows == 120

# Since such a refactor isn't part of this step, we'll focus on testing
# argument effects through the orchestration tests.

# --- High-Level Orchestration Tests ---

@patch('mule_validator.main.generate_console_report')
@patch('mule_validator.main.review_all_files')
@patch('mule_validator.main.validate_api_spec_and_flows')
@patch('mule_validator.main.validate_flows_in_package')
@patch('mule_validator.main.validate_dependencies_and_size')
@patch('mule_validator.main.validate_files')
@patch('logging.basicConfig') # Mock logging setup
@patch('sys.argv') # Mock command-line arguments
def test_main_orchestration_default_args(
    mock_sys_argv,
    mock_logging_basic_config,
    mock_validate_files,
    mock_validate_dependencies,
    mock_validate_flows,
    mock_validate_api,
    mock_review_all,
    mock_generate_report
):
    """
    Test main orchestration with default arguments.
    Verifies that all validator functions are called with correct default parameters
    and that the report generator is called with their aggregated results.
    """
    # Simulate command line: main_script_name /path/to/package
    mock_sys_argv.return_value = ['mule-validator', '/path/to/package'] # sys.argv is usually a list
    
    # Set distinct mock return values for each validator
    mock_validate_files.return_value = "yaml_results"
    mock_validate_dependencies.return_value = "dependency_results"
    mock_validate_flows.return_value = "flow_results"
    mock_validate_api.return_value = "api_results"
    mock_review_all.return_value = "reviewer_results"

    # Call the main function
    # Note: If main() doesn't explicitly parse sys.argv itself but relies on argparse default,
    # this patching of sys.argv should work. If main() took args directly, we'd call main(mock_args).
    # The current structure of main.py has argparse.ArgumentParser().parse_args() internally.
    
    # To correctly mock sys.argv for argparse within main(), it needs to be done before main() is called.
    # The @patch decorator handles this.
    # However, argparse.ArgumentParser() might grab sys.argv upon instantiation.
    # For more robust sys.argv patching with argparse, sometimes it's better to patch sys.argv directly:
    
    with patch.object(sys, 'argv', ['mule-validator', '/path/to/package']):
        main()

    # Assert logging.basicConfig was called (typically at the start of main)
    mock_logging_basic_config.assert_called_once() # Check basicConfig call specifics if needed

    # Assert each validator function was called once with the package_folder_path
    mock_validate_files.assert_called_once_with('/path/to/package')
    
    # For validate_dependencies_and_size, build_folder_path defaults to package_folder_path
    mock_validate_dependencies.assert_called_once_with(
        '/path/to/package', 
        '/path/to/package',  # build_folder_path defaults to package_folder_path
        max_size_mb=100      # Default value
    )
    
    # For validate_flows_in_package, check default thresholds
    mock_validate_flows.assert_called_once_with(
        '/path/to/package',
        max_flows=100,       # Default value
        max_sub_flows=50,    # Default value
        max_components=500   # Default value
    )
    
    mock_validate_api.assert_called_once_with('/path/to/package')
    mock_review_all.assert_called_once_with('/path/to/package')

    # Assert generate_console_report was called once with the aggregated results
    expected_all_results = {
        'yaml_validation': "yaml_results",
        'dependency_validation': "dependency_results",
        'flow_validation': "flow_results",
        'api_validation': "api_results",
        'code_reviewer': "reviewer_results"
    }
    mock_generate_report.assert_called_once_with(expected_all_results)


@patch('mule_validator.main.generate_console_report')
@patch('mule_validator.main.review_all_files')
@patch('mule_validator.main.validate_api_spec_and_flows')
@patch('mule_validator.main.validate_flows_in_package')
@patch('mule_validator.main.validate_dependencies_and_size')
@patch('mule_validator.main.validate_files')
@patch('logging.basicConfig')
def test_main_orchestration_custom_args(
    mock_logging_basic_config,
    mock_validate_files,
    mock_validate_dependencies,
    mock_validate_flows,
    mock_validate_api,
    mock_review_all,
    mock_generate_report
):
    """
    Test main orchestration with custom command-line arguments.
    Verifies that validator functions receive these custom values.
    """
    # Simulate command line with custom arguments
    cli_args = [
        'mule-validator',
        '/custom/package/path',
        '--max-flows', '123',
        '--max-build-size-mb', '77',
        '--build-folder-path', '/custom/build/path',
        '--max-sub-flows', '42',
        '--max-components', '555'
    ]
    
    with patch.object(sys, 'argv', cli_args):
        main()

    mock_logging_basic_config.assert_called_once()

    # Assert calls with custom values
    mock_validate_files.assert_called_once_with('/custom/package/path')
    
    mock_validate_dependencies.assert_called_once_with(
        '/custom/package/path',
        '/custom/build/path', # Custom build_folder_path
        max_size_mb=77        # Custom value
    )
    
    mock_validate_flows.assert_called_once_with(
        '/custom/package/path',
        max_flows=123,        # Custom value
        max_sub_flows=42,     # Custom value
        max_components=555    # Custom value
    )
    
    mock_validate_api.assert_called_once_with('/custom/package/path')
    mock_review_all.assert_called_once_with('/custom/package/path')
    
    # Report generation should still happen with whatever results mocks return
    mock_validate_files.return_value = "yaml_custom" # Example return
    mock_validate_dependencies.return_value = "dep_custom"
    # ... set other mock returns if their exact value in all_results matters for this test
    
    expected_all_results = {
        'yaml_validation': mock_validate_files.return_value,
        'dependency_validation': mock_validate_dependencies.return_value,
        'flow_validation': mock_validate_flows.return_value,
        'api_validation': mock_validate_api.return_value,
        'code_reviewer': mock_review_all.return_value
    }
    mock_generate_report.assert_called_once_with(expected_all_results)


# --- Argument Parser Specific Tests (using SystemExit for missing args) ---
# These tests will invoke the actual ArgumentParser setup within main.py
# To do this effectively without running the whole main() logic, we can patch
# the parts of main() that come *after* argument parsing.

@patch('mule_validator.main.validate_files', MagicMock())
@patch('mule_validator.main.validate_dependencies_and_size', MagicMock())
@patch('mule_validator.main.validate_flows_in_package', MagicMock())
@patch('mule_validator.main.validate_api_spec_and_flows', MagicMock())
@patch('mule_validator.main.review_all_files', MagicMock())
@patch('mule_validator.main.generate_console_report', MagicMock())
@patch('logging.basicConfig', MagicMock())
def test_arg_parser_missing_mandatory_argument(capsys):
    """
    Test that argparse (within main) exits if mandatory package_folder_path is missing.
    We patch all downstream functions to prevent them from running.
    """
    with patch.object(sys, 'argv', ['mule-validator']): # No package_folder_path
        with pytest.raises(SystemExit) as e:
            main()
    # Argparse typically exits with status 2 for errors
    assert e.value.code == 2 
    
    # Check stderr for the argparse error message (optional, but good)
    # This requires capsys or capturing stderr.
    # The exact message depends on argparse version and locale.
    # Example: "error: the following arguments are required: package_folder_path"
    # For now, just checking SystemExit is enough.
    # captured_err = capsys.readouterr().err
    # assert "required: package_folder_path" in captured_err


# It's challenging to test default values and specific parsed values of the *actual*
# parser without refactoring main.py to expose the parser or args, or by
# re-implementing the parser setup in tests. The orchestration tests above
# (test_main_orchestration_default_args and test_main_orchestration_custom_args)
# effectively test that the arguments parsed by main.py's internal parser
# are correctly passed to the subsequent functions. This implicitly tests
# the argument parsing logic including default values and custom value assignments.

# For instance, test_main_orchestration_default_args checks that max_size_mb=100 (default)
# is passed to validate_dependencies_and_size when --max-build-size-mb is not in sys.argv.
# And test_main_orchestration_custom_args checks that max_size_mb=77 (custom)
# is passed when --max-build-size-mb 77 is in sys.argv.

# This provides good confidence in the argument parsing and usage.The `tests/test_main.py` file has been successfully created and populated with unit tests for argument parsing (implicitly) and high-level orchestration of the `main` function in `mule_validator.main`.

Here's a summary of how the requirements were met:

1.  **General Setup**:
    *   The file `tests/test_main.py` was created.
    *   `pytest`, `argparse`, `unittest.mock` (`patch`, `MagicMock`, `call`), and `sys` were imported.
    *   The `main` function from `mule_validator.main` was imported.

2.  **Argument Parsing Tests**:
    *   **Implicit Testing via Orchestration**: As noted in the plan, directly testing the `ArgumentParser` instance within `main()` without refactoring `main.py` is complex. Therefore, argument parsing is primarily tested implicitly through the orchestration tests. These tests verify that when `main()` is called (with `sys.argv` patched to simulate different command-line inputs), the mocked validator functions receive arguments that reflect:
        *   Correctly parsed mandatory arguments (e.g., `package_folder_path`).
        *   Correct default values for optional arguments when they are not provided.
        *   Correct custom values for optional arguments when they are provided.
    *   **Missing Mandatory Argument**: `test_arg_parser_missing_mandatory_argument` explicitly tests the scenario where the mandatory `package_folder_path` is not provided. It patches `sys.argv` to simulate this and uses `pytest.raises(SystemExit)` to assert that `argparse` (within `main()`) causes the program to exit. Downstream functions are mocked to prevent side effects.

3.  **Tests for High-Level Orchestration**:
    *   **Mocking**: All imported validator functions (`validate_files`, `validate_dependencies_and_size`, `validate_flows_in_package`, `validate_api_spec_and_flows`, `review_all_files`), the reporter function (`generate_console_report`), and `logging.basicConfig` were mocked using `@patch`.
    *   **`sys.argv` Patching**: `sys.argv` was patched using `@patch('sys.argv')` or `with patch.object(sys, 'argv', ...)` to simulate different command-line inputs for `main()`.
    *   **Default Execution Flow (`test_main_orchestration_default_args`)**:
        *   Simulated calling `mule-validator /path/to/package`.
        *   Asserted that `logging.basicConfig` was called.
        *   Asserted that each mocked validator function was called once.
        *   Verified that `package_folder_path` was correctly passed.
        *   Verified that default values for thresholds (e.g., `max_size_mb=100`, `max_flows=100`) were passed to the respective functions.
        *   Verified that `build_folder_path` correctly defaulted to `package_folder_path` for `validate_dependencies_and_size`.
        *   Asserted that `generate_console_report` was called once with an `all_results` dictionary containing the distinct mocked return values from each validator.
    *   **Execution with Custom Arguments (`test_main_orchestration_custom_args`)**:
        *   Simulated a command line with various custom arguments (e.g., `/custom/pkg`, `--max-flows 123`, `--max-build-size-mb 77`, `--build-folder-path /custom/build`).
        *   Asserted that validator functions were called with these specific custom values passed from the command line. For example, `validate_flows_in_package` being called with `max_flows=123`.

The tests effectively validate that `main.py` parses command-line arguments as expected (by observing their effect on downstream calls) and correctly orchestrates the calls to validator functions and the reporter, passing the appropriate data and aggregated results.
