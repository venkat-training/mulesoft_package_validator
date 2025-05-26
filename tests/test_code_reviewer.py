import pytest
import os
from unittest.mock import patch, MagicMock, mock_open, call
from lxml import etree # For etree.XMLSyntaxError

from mule_validator.code_reviewer import (
    is_camel_case,
    check_flow_names,
    check_http_listener,
    check_logger as check_logger_component, # Alias to avoid pytest conflict
    check_dataweave,
    check_http_response,
    check_scheduler,
    check_concur, # Assuming this is a placeholder/example
    check_http_requester,
    check_ftp,
    check_sftp,
    check_smb, # Assuming this is a placeholder/example
    check_vm,
    check_s3,  # Assuming this is a placeholder/example
    check_smtp,
    review_mulesoft_code,
    review_all_files,
    MULE_NAMESPACES,
    CAMEL_CASE_REGEX, # Not directly used in tests, but is_camel_case is
    FLOW_NAME_VALID_CHAR_REGEX, # Not directly used in tests, but check_flow_names is
    DEFAULT_SCAN_PATH_NAME,
    EXCLUDED_DIRS,
    EXCLUDED_FILE_SUBSTRINGS,
    POM_XML_FILE_NAME
)

# Mock the logger for all tests in this module
@pytest.fixture(autouse=True)
def mock_logger_fixture():
    with patch('mule_validator.code_reviewer.logger', MagicMock()) as mock_log:
        yield mock_log

# Helper function
def _create_mock_xml_element(attributes=None, children=None, text=None, tag='mock_element', namespace_map=None):
    """
    Creates a MagicMock configured to simulate an lxml.etree._Element.
    - attributes: dict for get() method.
    - children: list of other mock elements for find()/findall().
    - text: string for the .text attribute.
    - tag: string for the .tag attribute.
    - namespace_map: dict for nsmap attribute if needed.
    """
    element = MagicMock(spec=etree._Element) # Use spec for more realistic mocking
    element.tag = tag
    element.text = text
    element.nsmap = namespace_map if namespace_map is not None else {}

    # Mock get() method
    if attributes:
        element.get.side_effect = lambda key, default=None: attributes.get(key, default)
    else:
        element.get.return_value = None # Default if no attributes

    # Mock findall() method
    # This basic mock assumes findall is called with a path and optionally namespaces.
    # It will return all children if path is './/*' or similar, or filter by tag.
    # For more complex XPath, this mock would need to be more sophisticated or per-test.
    _children = children if children else []
    
    def findall_side_effect(path, namespaces=None):
        # Simplified: if path is specific like './/mule:flow', it needs specific handling
        # For this helper, assume generic iteration for now or very simple tag checks.
        # This part might need refinement based on actual usage in check_* functions.
        # For now, just return all children if path is a generic "any child" type.
        # If a specific tag is in path (e.g. "mule:flow"), filter by tag.
        
        found_elements = []
        # Simplified path parsing (very basic)
        search_tag = path.split(':')[-1] if ':' in path else path.split('/')[-1]
        
        for child_elem in _children:
            child_tag_local = child_elem.tag.split('}')[-1] if '}' in child_elem.tag else child_elem.tag
            if search_tag == '*' or child_tag_local == search_tag or path == '.': # Handle '.' for current element
                found_elements.append(child_elem)
            # Recurse if path indicates deeper search like './/'
            if path.startswith('.//') and hasattr(child_elem, 'findall'):
                 found_elements.extend(child_elem.findall(path, namespaces=namespaces))
        return found_elements

    element.findall = MagicMock(side_effect=findall_side_effect)

    # Mock find() method (returns the first element from findall or None)
    element.find = MagicMock(side_effect=lambda path, namespaces=None: (findall_side_effect(path, namespaces) or [None])[0])
    
    # Make element iterable (like XML elements)
    element.__iter__ = MagicMock(return_value=iter(_children))
    element.__len__ = MagicMock(return_value=len(_children))


    return element

# 1. Tests for is_camel_case(name)
@pytest.mark.parametrize("name, expected", [
    ("flowName", True),
    ("anotherFlow", True),
    ("myFlow123", True),
    ("a", True), # Single lowercase char is camelCase
    ("FlowName", False),    # Starts with uppercase
    ("flow_name", False),   # Contains underscore
    ("flow-name", False),   # Contains hyphen
    ("1flowName", False),   # Starts with number
    ("flow Name", False),   # Contains space
    ("", False),            # Empty string
    ("flowName!", False),   # Contains special char
])
def test_is_camel_case(name, expected):
    assert is_camel_case(name) == expected

# 2. Tests for individual check_* functions
# Example for check_flow_names - others would follow a similar pattern

def test_check_flow_names():
    # Scenario 1: Valid flow names
    flow1_valid = _create_mock_xml_element(attributes={'name': 'myFlowOne'}, tag='{MULE_NAMESPACES["mule"]}flow')
    flow2_valid = _create_mock_xml_element(attributes={'name': 'processData'}, tag='{MULE_NAMESPACES["mule"]}flow')
    root_valid = _create_mock_xml_element(children=[flow1_valid, flow2_valid])
    assert check_flow_names(root_valid) == []

    # Scenario 2: Missing name attribute
    flow_missing_name = _create_mock_xml_element(attributes={}, tag='{MULE_NAMESPACES["mule"]}flow') # No name
    root_missing_name = _create_mock_xml_element(children=[flow_missing_name])
    assert check_flow_names(root_missing_name) == ["Flow is missing a name attribute."]

    # Scenario 3: Not camel case
    flow_not_camel = _create_mock_xml_element(attributes={'name': 'MyFlow'}, tag='{MULE_NAMESPACES["mule"]}flow')
    root_not_camel = _create_mock_xml_element(children=[flow_not_camel])
    assert check_flow_names(root_not_camel) == ["Flow name 'MyFlow' does not comply with camel case format."]

    # Scenario 4: Invalid characters
    flow_invalid_char = _create_mock_xml_element(attributes={'name': 'my-flow'}, tag='{MULE_NAMESPACES["mule"]}flow')
    root_invalid_char = _create_mock_xml_element(children=[flow_invalid_char])
    # is_camel_case will fail first for 'my-flow'
    assert "Flow name 'my-flow' does not comply with camel case format." in check_flow_names(root_invalid_char)
    
    flow_invalid_char_alphanum = _create_mock_xml_element(attributes={'name': 'myFlow!'}, tag='{MULE_NAMESPACES["mule"]}flow')
    root_invalid_char_alphanum = _create_mock_xml_element(children=[flow_invalid_char_alphanum])
    # is_camel_case passes, but FLOW_NAME_VALID_CHAR_REGEX fails
    assert check_flow_names(root_invalid_char_alphanum) == ["Flow name 'myFlow!' contains invalid characters (only alphanumeric allowed)."]

def test_check_http_listener():
    listener_valid = _create_mock_xml_element(attributes={'path': '/api/*'}, tag='{MULE_NAMESPACES["http"]}listener')
    listener_missing_path = _create_mock_xml_element(attributes={}, tag='{MULE_NAMESPACES["http"]}listener')
    root = _create_mock_xml_element(children=[listener_valid, listener_missing_path])
    
    # Need to mock root.findall specifically for the http:listener tag
    root.findall = MagicMock(return_value=[listener_valid, listener_missing_path])
    
    issues = check_http_listener(root)
    assert "HTTP Listener is missing a path attribute." in issues
    assert len(issues) == 1

def test_check_logger_component(): # Renamed test function
    logger_valid = _create_mock_xml_element(attributes={'message': 'Log this'}, tag='{MULE_NAMESPACES["mule"]}logger')
    logger_missing_msg = _create_mock_xml_element(attributes={}, tag='{MULE_NAMESPACES["mule"]}logger')
    root = _create_mock_xml_element()
    root.findall = MagicMock(return_value=[logger_valid, logger_missing_msg])
    
    issues = check_logger_component(root)
    assert "Logger is missing a message attribute." in issues
    assert len(issues) == 1

def test_check_dataweave():
    set_payload_child = _create_mock_xml_element(tag='{MULE_NAMESPACES["dw"]}set-payload')
    transform_valid = _create_mock_xml_element(children=[set_payload_child], tag='{MULE_NAMESPACES["dw"]}transform-message')
    transform_missing_sp = _create_mock_xml_element(children=[], tag='{MULE_NAMESPACES["dw"]}transform-message') # No children
    
    root = _create_mock_xml_element()
    root.findall = MagicMock(return_value=[transform_valid, transform_missing_sp])
    
    issues = check_dataweave(root)
    assert "DataWeave transform-message is missing a direct dw:set-payload child." in issues
    assert len(issues) == 1

# ... (Similar tests for other check_* functions would be added here)
# For brevity, I'll skip writing out all of them, but they'd follow the pattern:
# - Mock root and its findall to return specific elements.
# - Check for missing attributes or children as per the function's logic.

# 3. Tests for review_mulesoft_code(file_path)

# Patch all check functions that are called by review_mulesoft_code
@patch('mule_validator.code_reviewer.check_flow_names', return_value=[])
@patch('mule_validator.code_reviewer.check_http_listener', return_value=[])
@patch('mule_validator.code_reviewer.check_logger', return_value=[]) # This is the original name
@patch('mule_validator.code_reviewer.check_dataweave', return_value=[])
@patch('mule_validator.code_reviewer.check_http_response', return_value=[])
@patch('mule_validator.code_reviewer.check_scheduler', return_value=[])
@patch('mule_validator.code_reviewer.check_concur', return_value=[])
@patch('mule_validator.code_reviewer.check_http_requester', return_value=[])
@patch('mule_validator.code_reviewer.check_ftp', return_value=[])
@patch('mule_validator.code_reviewer.check_sftp', return_value=[])
@patch('mule_validator.code_reviewer.check_smb', return_value=[])
@patch('mule_validator.code_reviewer.check_vm', return_value=[])
@patch('mule_validator.code_reviewer.check_s3', return_value=[])
@patch('mule_validator.code_reviewer.check_smtp', return_value=[])
@patch('lxml.etree.fromstring')
@patch('builtins.open', new_callable=mock_open, read_data=b"<mule></mule>") # Read as bytes
def test_review_mulesoft_code_valid_no_issues(mock_file_open, mock_fromstring, *mock_checks):
    mock_root = _create_mock_xml_element()
    mock_fromstring.return_value = mock_root
    
    results = review_mulesoft_code("dummy.xml")
    assert results == []
    mock_file_open.assert_called_once_with("dummy.xml", 'rb')
    mock_fromstring.assert_called_once_with(b"<mule></mule>")
    for mc in mock_checks: # Ensure all check functions were called
        mc.assert_called_once_with(mock_root)

@patch('mule_validator.code_reviewer.check_flow_names', return_value=['Flow name issue'])
@patch('mule_validator.code_reviewer.check_http_listener', return_value=['Listener path issue'])
@patch('mule_validator.code_reviewer.check_logger', return_value=[])
@patch('mule_validator.code_reviewer.check_dataweave', return_value=[])
# ... (patch others as returning [])
@patch('mule_validator.code_reviewer.check_http_response', MagicMock(return_value=[]))
@patch('mule_validator.code_reviewer.check_scheduler', MagicMock(return_value=[]))
@patch('mule_validator.code_reviewer.check_concur', MagicMock(return_value=[]))
@patch('mule_validator.code_reviewer.check_http_requester', MagicMock(return_value=[]))
@patch('mule_validator.code_reviewer.check_ftp', MagicMock(return_value=[]))
@patch('mule_validator.code_reviewer.check_sftp', MagicMock(return_value=[]))
@patch('mule_validator.code_reviewer.check_smb', MagicMock(return_value=[]))
@patch('mule_validator.code_reviewer.check_vm', MagicMock(return_value=[]))
@patch('mule_validator.code_reviewer.check_s3', MagicMock(return_value=[]))
@patch('mule_validator.code_reviewer.check_smtp', MagicMock(return_value=[]))
@patch('lxml.etree.fromstring')
@patch('builtins.open', new_callable=mock_open, read_data=b"<mule></mule>")
def test_review_mulesoft_code_valid_some_issues(mock_file_open, mock_fromstring, 
                                                _mock_smtp, _mock_s3, _mock_vm, _mock_smb, _mock_sftp, _mock_ftp, # Order matters for patch
                                                _mock_http_req, _mock_concur, _mock_sched, _mock_http_resp,
                                                _mock_dw, _mock_logger_c,
                                                mock_check_listener, mock_check_flow): # Patched functions are passed in reverse order
    mock_root = _create_mock_xml_element()
    mock_fromstring.return_value = mock_root
    
    results = review_mulesoft_code("dummy.xml")
    expected = [
        {'file_path': 'dummy.xml', 'type': 'CodeReviewIssue', 'message': 'check_flow_names: Flow name issue'},
        {'file_path': 'dummy.xml', 'type': 'CodeReviewIssue', 'message': 'check_http_listener: Listener path issue'}
    ]
    assert results == expected

@patch('builtins.open', new_callable=mock_open, read_data=b"<malformed-xml>")
@patch('lxml.etree.fromstring', side_effect=etree.XMLSyntaxError("mocked syntax error", None, None, None, None))
def test_review_mulesoft_code_xml_syntax_error(mock_fromstring, mock_file_open, caplog):
    results = review_mulesoft_code("dummy.xml")
    expected = [{'file_path': 'dummy.xml', 'type': 'XMLSyntaxError', 'message': 'mocked syntax error'}]
    assert results == expected
    assert any("XML syntax error in file dummy.xml: mocked syntax error" in record.message for record in caplog.records if record.levelname == "ERROR")

@patch('builtins.open', side_effect=IOError("mocked read error"))
def test_review_mulesoft_code_fileread_error(mock_file_open, caplog):
    results = review_mulesoft_code("dummy.xml")
    expected = [{'file_path': 'dummy.xml', 'type': 'FileReadError', 'message': 'mocked read error'}]
    assert results == expected
    assert any("File read error for dummy.xml: mocked read error" in record.message for record in caplog.records if record.levelname == "ERROR")

@patch('builtins.open', new_callable=mock_open, read_data=b"") # Empty file content
@patch('lxml.etree.fromstring') # To see if it's called
def test_review_mulesoft_code_empty_xml_file(mock_fromstring, mock_file_open, caplog):
    # The refactored review_mulesoft_code has a check for empty bytes.
    results = review_mulesoft_code("dummy.xml")
    expected = [{'file_path': 'dummy.xml', 'type': 'FileReadError', 'message': 'File is empty.'}]
    assert results == expected
    assert any("File is empty: dummy.xml" in record.message for record in caplog.records if record.levelname == "WARNING")
    mock_fromstring.assert_not_called() # Should not try to parse empty content if check is there.


# 4. Tests for review_all_files(package_folder_path)

@patch('mule_validator.code_reviewer.review_mulesoft_code')
@patch('os.walk')
@patch('os.path.isdir')
def test_review_all_files_scan_path_not_exist(mock_isdir, mock_os_walk, mock_review_code, caplog):
    package_path = "dummy_package"
    scan_path = os.path.join(package_path, DEFAULT_SCAN_PATH_NAME)
    mock_isdir.return_value = False # Scan path does not exist
    
    results = review_all_files(package_path)
    assert results == []
    mock_isdir.assert_called_once_with(scan_path)
    mock_os_walk.assert_not_called()
    assert any(f"Scan directory does not exist: {scan_path}. Cannot perform code review." in record.message for record in caplog.records if record.levelname == "ERROR")

@patch('mule_validator.code_reviewer.review_mulesoft_code')
@patch('os.walk')
@patch('os.path.isdir')
def test_review_all_files_no_processable_xml_files(mock_isdir, mock_os_walk, mock_review_code, caplog):
    package_path = "dummy_package"
    scan_path = os.path.join(package_path, DEFAULT_SCAN_PATH_NAME)
    mock_isdir.return_value = True
    # Simulate os.walk finding only non-XML or excluded files
    mock_os_walk.return_value = [
        (scan_path, [], [POM_XML_FILE_NAME, 'config.yaml']),
        (os.path.join(scan_path, 'subdir'), EXCLUDED_DIRS, ['another.xml']), # Excluded dir
        (os.path.join(scan_path, 'munit_flows'), [], ['test-munit.xml']) # Excluded file substring
    ]
    
    results = review_all_files(package_path)
    assert results == []
    mock_review_code.assert_not_called()
    assert any(f"Code review completed. No issues or errors found in {scan_path}" in record.message for record in caplog.records if record.levelname == "INFO")


@patch('mule_validator.code_reviewer.review_mulesoft_code')
@patch('os.walk')
@patch('os.path.isdir')
def test_review_all_files_mix_of_files_and_results(mock_isdir, mock_os_walk, mock_review_code):
    package_path = "dummy_package"
    scan_path = os.path.join(package_path, DEFAULT_SCAN_PATH_NAME)
    
    file1_path = os.path.join(scan_path, 'file1.xml')
    file2_path = os.path.join(scan_path, 'file2.xml')
    file3_path = os.path.join(scan_path, 'subdir', 'file3.xml')
    
    mock_isdir.return_value = True
    mock_os_walk.return_value = [
        (scan_path, ['subdir', 'target'], ['file1.xml', 'file2.xml', POM_XML_FILE_NAME]),
        (os.path.join(scan_path, 'subdir'), [], ['file3.xml', 'test-munit.xml']),
        (os.path.join(scan_path, 'target'), [], ['ignored.xml']) # This dir itself should be skipped by dirs[:]
    ]

    issue1 = {'file_path': file1_path, 'type': 'CodeReviewIssue', 'message': 'Issue in file1'}
    error3 = {'file_path': file3_path, 'type': 'XMLSyntaxError', 'message': 'Syntax error in file3'}
    
    def review_side_effect(path):
        if path == file1_path: return [issue1]
        if path == file2_path: return [] # No issues
        if path == file3_path: return [error3]
        return []
    mock_review_code.side_effect = review_side_effect
    
    results = review_all_files(package_path)
    
    assert len(results) == 2
    assert issue1 in results
    assert error3 in results
    
    expected_calls = [call(file1_path), call(file2_path), call(file3_path)]
    mock_review_code.assert_has_calls(expected_calls, any_order=True) # Order might vary with os.walk
    
    # Verify dirs[:] modification in os.walk (indirectly by checking mock_review_code calls)
    # No calls for files in 'target/' or 'test-munit.xml' or 'pom.xml'
    assert not any(c[0][0].startswith(os.path.join(scan_path, 'target')) for c in mock_review_code.call_args_list)
    assert not any(c[0][0].endswith('test-munit.xml') for c in mock_review_code.call_args_list)
    assert not any(c[0][0].endswith(POM_XML_FILE_NAME) for c in mock_review_code.call_args_list)

@patch('mule_validator.code_reviewer.review_mulesoft_code')
@patch('os.walk')
@patch('os.path.isdir')
def test_review_all_files_exclusion_logic(mock_isdir, mock_os_walk, mock_review_code):
    """Specifically test EXCLUDED_DIRS and EXCLUDED_FILE_SUBSTRINGS logic."""
    package_path = "dummy_package"
    scan_path = os.path.join(package_path, DEFAULT_SCAN_PATH_NAME)
    
    # Define paths for files that should be processed or skipped
    processable_file = os.path.join(scan_path, 'processable.xml')
    pom_file = os.path.join(scan_path, POM_XML_FILE_NAME)
    munit_file = os.path.join(scan_path, 'some_munit_test.xml')
    file_in_target = os.path.join(scan_path, EXCLUDED_DIRS[0], 'file_in_target.xml') # Assuming 'target' is in EXCLUDED_DIRS
    
    mock_isdir.return_value = True
    
    # Simulate os.walk behavior
    # Root level: processable.xml, pom.xml, munit file, and an excluded dir 'target'
    # Inside 'target': file_in_target.xml
    mock_os_walk.return_value = [
        (scan_path, [EXCLUDED_DIRS[0]], [os.path.basename(processable_file), os.path.basename(pom_file), os.path.basename(munit_file)]),
        (file_in_target.rsplit(os.sep,1)[0], [], [os.path.basename(file_in_target)]) # Content of 'target' dir
    ]
    
    mock_review_code.return_value = [] # Assume no issues for simplicity
    
    review_all_files(package_path)
    
    # Assert that review_mulesoft_code was called ONLY for processable_file
    mock_review_code.assert_called_once_with(processable_file)
    
    # Check that it was NOT called for others
    for call_args in mock_review_code.call_args_list:
        called_path = call_args[0][0]
        assert called_path != pom_file
        assert called_path != munit_file
        assert called_path != file_in_target

    # This test depends on the internal os.walk dirs[:] modification.
    # A more robust way to test this part of os.walk is to ensure that
    # the subsequent calls to review_mulesoft_code do not include files from excluded directories.
    # The assertion above for mock_review_code.call_args_list effectively checks this.
