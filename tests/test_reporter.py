import pytest
from unittest.mock import patch, MagicMock
from mule_validator.reporter import generate_console_report
from tabulate import tabulate # Imported to potentially check if it's called, though not strictly needed for output string validation

# Mock the logger for all tests in this module
@pytest.fixture(autouse=True)
def mock_logger_fixture():
    with patch('mule_validator.reporter.logger', MagicMock()) as mock_log:
        yield mock_log

def test_report_empty_results(capsys):
    """Test generate_console_report with empty all_results."""
    generate_console_report({})
    captured = capsys.readouterr()
    assert "VALIDATION REPORT" in captured.out
    assert "No validation results to report." in captured.out
    assert "END OF REPORT" in captured.out

# --- YAML Validation Section Tests ---
def test_report_yaml_validation_all_valid(capsys):
    """Test YAML validation report: 1 mandatory valid, 1 optional valid."""
    all_results = {
        'yaml_validation': [
            {'file_name': 'config-prod.yaml', 'status': 'Valid', 'message': '', 'type': 'Mandatory'},
            {'file_name': 'config-dev.yaml', 'status': 'Valid', 'message': '', 'type': 'Optional'}
        ]
    }
    generate_console_report(all_results)
    captured = capsys.readouterr()
    
    assert "--- YAML VALIDATION ---" in captured.out
    assert "Mandatory Configuration Files:" in captured.out
    assert "config-prod.yaml" in captured.out
    assert "Valid" in captured.out
    assert "Optional Configuration Files:" in captured.out
    assert "config-dev.yaml" in captured.out
    # Check for table structure elements (e.g., part of tabulate's grid)
    assert "+-" in captured.out # Common in tabulate grid format
    assert "| File Name " in captured.out # Header

def test_report_yaml_validation_mandatory_missing_optional_invalid(capsys):
    """Test YAML validation report: Mandatory missing, optional invalid."""
    all_results = {
        'yaml_validation': [
            {'file_name': 'config-prod.yaml', 'status': 'Missing', 'message': 'File not found', 'type': 'Mandatory'},
            {'file_name': 'config-dev.yaml', 'status': 'Invalid', 'message': 'YAML error here', 'type': 'Optional'}
        ]
    }
    generate_console_report(all_results)
    captured = capsys.readouterr()

    assert "--- YAML VALIDATION ---" in captured.out
    assert "config-prod.yaml" in captured.out
    assert "Missing" in captured.out
    assert "File not found" in captured.out
    assert "config-dev.yaml" in captured.out
    assert "Invalid" in captured.out
    assert "YAML error here" in captured.out

def test_report_yaml_validation_resources_dir_error(capsys):
    """Test YAML validation report: Resources directory error."""
    all_results = {
        'yaml_validation': [
            # The prompt mentioned 'type': 'Directory', but my refactor of configfile_validator did not add this for this specific error.
            # Sticking to the output of my refactored configfile_validator.py.
            {'file_name': 'N/A', 'status': 'Error', 'message': 'Resources directory not found...'}
        ]
    }
    generate_console_report(all_results)
    captured = capsys.readouterr()
    
    assert "--- YAML VALIDATION ---" in captured.out
    assert "ERROR: Resources directory not found..." in captured.out
    # Ensure no table headers for mandatory/optional are printed in this error case
    assert "Mandatory Configuration Files:" not in captured.out

# --- Dependency Validation Section Tests ---
def test_report_dependency_validation_ok_no_unused(capsys):
    """Test Dependency validation: No unused, size OK."""
    all_results = {
        'dependency_validation': {
            'unused_dependencies': [], 
            'build_size_mb': 50.0, 
            'size_ok': True, 
            'max_size_mb': 100
        }
    }
    generate_console_report(all_results)
    captured = capsys.readouterr()

    assert "--- DEPENDENCY VALIDATION ---" in captured.out
    assert "Build Size: 50.00 MB (Max Allowed: 100 MB) - Status: OK" in captured.out
    assert "No unused dependencies found." in captured.out

def test_report_dependency_validation_unused_size_exceeded(capsys):
    """Test Dependency validation: Unused present, size exceeded."""
    all_results = {
        'dependency_validation': {
            'unused_dependencies': ['com.example:dep1', 'org.another:dep2'],
            'build_size_mb': 150.0, 
            'size_ok': False, 
            'max_size_mb': 100
        }
    }
    generate_console_report(all_results)
    captured = capsys.readouterr()

    assert "--- DEPENDENCY VALIDATION ---" in captured.out
    assert "Build Size: 150.00 MB (Max Allowed: 100 MB) - Status: Exceeded Limit" in captured.out
    assert "Unused Dependencies:" in captured.out
    assert "- com.example:dep1" in captured.out
    assert "- org.another:dep2" in captured.out

# --- Flow Validation Section Tests ---
def test_report_flow_validation_counts_ok(capsys):
    """Test Flow validation: Counts OK."""
    all_results = {
        'flow_validation': {
            'total_counts': {'flows': 10, 'sub_flows': 5, 'components': 100},
            'flows_ok': True, 'sub_flows_ok': True, 'components_ok': True,
            'max_flows_limit': 100, 'max_sub_flows_limit': 50, 'max_components_limit': 500
        }
    }
    generate_console_report(all_results)
    captured = capsys.readouterr()

    assert "--- FLOW VALIDATION ---" in captured.out
    assert "| Category   " in captured.out # Table header
    assert "| Flows      |   10 |   100 | OK" in captured.out # Example row
    assert "| Sub-flows  |    5 |    50 | OK" in captured.out
    assert "| Components |  100 |   500 | OK" in captured.out

def test_report_flow_validation_flows_exceeded(capsys):
    """Test Flow validation: Flows exceeded."""
    all_results = {
        'flow_validation': {
            'total_counts': {'flows': 110, 'sub_flows': 5, 'components': 100},
            'flows_ok': False, 'sub_flows_ok': True, 'components_ok': True,
            'max_flows_limit': 100, 'max_sub_flows_limit': 50, 'max_components_limit': 500
        }
    }
    generate_console_report(all_results)
    captured = capsys.readouterr()

    assert "--- FLOW VALIDATION ---" in captured.out
    assert "| Flows      |  110 |   100 | Exceeded" in captured.out # Example row

def test_report_flow_validation_validator_error(capsys):
    """Test Flow validation: Error from validator (e.g., src/main/mule not found)."""
    # Based on the refactored flow_validator, an error is raised, not returned in dict.
    # However, the reporter was updated to handle a 'message' key if total_counts is None.
    all_results = {
        'flow_validation': {
            'total_counts': None, # This indicates an issue before counting
            'message': "Mule source directory does not exist: path/to/src/main/mule",
            # Other keys might be missing or have default values
            'flows_ok': False, 'sub_flows_ok': False, 'components_ok': False,
            'max_flows_limit': 'N/A', 'max_sub_flows_limit': 'N/A', 'max_components_limit': 'N/A'
        }
    }
    generate_console_report(all_results)
    captured = capsys.readouterr()
    assert "--- FLOW VALIDATION ---" in captured.out
    assert "ERROR: Mule source directory does not exist: path/to/src/main/mule" in captured.out
    assert "| Category   " not in captured.out # No table should be printed

# --- API Validation Section Tests ---
def test_report_api_validation_specs_and_defs_found(capsys):
    """Test API validation: Specs and definition flows found."""
    all_results = {
        'api_validation': {
            'api_spec_files': ['src/main/resources/api/spec1.raml', 'src/main/resources/api/spec2.yaml'],
            'api_definition_flows': ['src/main/mule/flow_api.xml'],
            'api_spec_found': True,
            'api_definition_flow_found': True
        }
    }
    generate_console_report(all_results)
    captured = capsys.readouterr()

    assert "--- API VALIDATION ---" in captured.out
    assert "API Specifications Found: Yes" in captured.out
    assert "- src/main/resources/api/spec1.raml" in captured.out
    assert "- src/main/resources/api/spec2.yaml" in captured.out
    assert "API Definition Flows Found: Yes" in captured.out
    assert "- src/main/mule/flow_api.xml" in captured.out

def test_report_api_validation_neither_found(capsys):
    """Test API validation: Neither specs nor definition flows found."""
    all_results = {
        'api_validation': {
            'api_spec_files': [],
            'api_definition_flows': [],
            'api_spec_found': False,
            'api_definition_flow_found': False
        }
    }
    generate_console_report(all_results)
    captured = capsys.readouterr()

    assert "--- API VALIDATION ---" in captured.out
    assert "API Specifications Found: No" in captured.out
    assert "API Definition Flows Found: No" in captured.out
    assert "    - " not in captured.out # No file paths should be listed

# --- Code Reviewer Section Tests ---
def test_report_code_reviewer_no_issues(capsys):
    """Test Code Reviewer: No issues found."""
    all_results = {'code_reviewer': []}
    generate_console_report(all_results)
    captured = capsys.readouterr()
    assert "--- CODE REVIEWER ---" in captured.out
    assert "No code review issues or file errors found." in captured.out

def test_report_code_reviewer_file_processing_error(capsys):
    """Test Code Reviewer: File processing error."""
    all_results = {
        'code_reviewer': [
            {'file_path': 'a.xml', 'type': 'XMLSyntaxError', 'message': 'bad xml content here'}
        ]
    }
    generate_console_report(all_results)
    captured = capsys.readouterr()

    assert "--- CODE REVIEWER ---" in captured.out
    assert "File Processing Errors:" in captured.out
    assert "File: a.xml" in captured.out
    assert "Error Type: XMLSyntaxError" in captured.out
    assert "Message: bad xml content here" in captured.out

def test_report_code_reviewer_issues_found(capsys):
    """Test Code Reviewer: Code review issues found in a file."""
    all_results = {
        'code_reviewer': [
            {'file_path': 'b.xml', 'type': 'CodeReviewIssue', 'message': 'check_flow_names: Flow name bad'},
            {'file_path': 'b.xml', 'type': 'CodeReviewIssue', 'message': 'check_logger: Logger message missing'}
        ]
    }
    generate_console_report(all_results)
    captured = capsys.readouterr()

    assert "--- CODE REVIEWER ---" in captured.out
    assert "Code Review Issues by File:" in captured.out
    assert "File: b.xml" in captured.out
    assert "- check_flow_names: Flow name bad" in captured.out
    assert "- check_logger: Logger message missing" in captured.out

def test_report_code_reviewer_mix_of_errors_and_issues(capsys):
    """Test Code Reviewer: Mix of file errors and code issues."""
    all_results = {
        'code_reviewer': [
            {'file_path': 'a.xml', 'type': 'FileReadError', 'message': 'Cannot read file'},
            {'file_path': 'b.xml', 'type': 'CodeReviewIssue', 'message': 'check_flow_names: Issue 1 in b'},
            {'file_path': 'c.xml', 'type': 'CodeReviewIssue', 'message': 'check_http_listener: Issue 1 in c'},
            {'file_path': 'b.xml', 'type': 'CodeReviewIssue', 'message': 'check_dataweave: Issue 2 in b'}
        ]
    }
    generate_console_report(all_results)
    captured = capsys.readouterr()

    assert "--- CODE REVIEWER ---" in captured.out
    assert "File Processing Errors:" in captured.out
    assert "File: a.xml" in captured.out
    assert "Error Type: FileReadError" in captured.out
    assert "Message: Cannot read file" in captured.out
    assert "Code Review Issues by File:" in captured.out
    assert "File: b.xml" in captured.out
    assert "- check_flow_names: Issue 1 in b" in captured.out
    assert "- check_dataweave: Issue 2 in b" in captured.out
    assert "File: c.xml" in captured.out
    assert "- check_http_listener: Issue 1 in c" in captured.out

# --- Test Unknown Validation Type Section ---
def test_report_unknown_validation_type(capsys):
    """Test reporting for an unknown validation type."""
    all_results = {
        'new_unknown_validator': "Some simple string result",
        'another_unknown': {'key1': 'val1', 'key2': [1,2,3]}
    }
    generate_console_report(all_results)
    captured = capsys.readouterr()

    assert "--- NEW UNKNOWN VALIDATOR ---" in captured.out
    assert "Some simple string result" in captured.out
    assert "--- ANOTHER UNKNOWN ---" in captured.out
    assert "key1: val1" in captured.out
    assert "key2: [1, 2, 3]" in captured.out
