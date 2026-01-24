import pytest
import os
import xml.etree.ElementTree as ET
from unittest.mock import patch, MagicMock, call

from mule_validator.flow_validator import (
    count_flows_and_components,
    validate_flows_in_package,
    MULE_CORE_NAMESPACE_URI,
    IGNORED_FLOW_NAME_SUBSTRINGS, # Corrected from IGNORED_FLOW_NAMES
    COMMON_MIME_TYPES,
    validate_flow_name_camel_case, # Import for direct testing
    is_camel_case # Import for direct testing (optional, if needed for specific assertions)
)

# Mock the logger for all tests in this module
@pytest.fixture(autouse=True)
def mock_logger_fixture():
    with patch('mule_validator.flow_validator.logger', MagicMock()) as mock_log:
        yield mock_log

# 1. Tests for count_flows_and_components(xml_file_path)

@patch('xml.etree.ElementTree.parse')
def test_count_flows_and_components_valid_xml_variants(mock_et_parse):
    """Test count_flows_and_components with various valid XML structures."""
    
    # Helper to create mock elements with a 'len' for component counting
    def create_mock_element_with_components(num_components):
        mock_elem = MagicMock()
        # Mocking the __len__ method for an Element object is tricky as it's not standard.
        # The code `len(flow)` or `len(sub_flow)` implies it iterates over children.
        # So, we'll mock the result of findall('*') or make it iterable with a certain number of items.
        # A simpler way for this specific test is to assume `len(element)` works if element is a list-like object.
        # Let's assume the elements are directly iterable and have a length.
        # If not, we'd mock them as iterables (e.g., mock_elem.__iter__.return_value = iter([MagicMock()] * num_components))
        # Or, if the code is `len(list(element))`, then this is fine.
        # The actual `len(xml.etree.ElementTree.Element)` counts direct children.
        
        # Let's mock it as if it's a list of children
        children = [MagicMock() for _ in range(num_components)]
        mock_elem.__len__.return_value = len(children) # if the code uses len() directly on the element
        # If the code does `for child in element: ...`, then mock __iter__
        mock_elem.__iter__.return_value = iter(children)
        return mock_elem

    test_cases = [
        ("flows_only", [create_mock_element_with_components(3), create_mock_element_with_components(2)], [], 2, 0, 5),
        ("sub_flows_only", [], [create_mock_element_with_components(4)], 0, 1, 4),
        ("mixed_flows", [create_mock_element_with_components(1)], [create_mock_element_with_components(2)], 1, 1, 3),
        ("no_flows_or_subflows", [], [], 0, 0, 0),
        ("empty_flows", [create_mock_element_with_components(0)], [create_mock_element_with_components(0)], 1, 1, 0),
    ]

    for name, mock_flows, mock_sub_flows, exp_f, exp_sf, exp_c in test_cases:
        mock_root = MagicMock()
        mock_root.findall(f'.//{{{MULE_CORE_NAMESPACE_URI}}}flow').return_value = mock_flows
        mock_root.findall(f'.//{{{MULE_CORE_NAMESPACE_URI}}}sub-flow').return_value = mock_sub_flows
        
        mock_tree = MagicMock()
        mock_tree.getroot.return_value = mock_root
        mock_et_parse.return_value = mock_tree
        
        counts, _ = count_flows_and_components("dummy.xml")
        
        assert counts['flows'] == exp_f, f"Test '{name}' failed for flows"
        assert counts['sub_flows'] == exp_sf, f"Test '{name}' failed for sub-flows"
        assert counts['components'] == exp_c, f"Test '{name}' failed for components"
        mock_et_parse.assert_called_with("dummy.xml") # Called for each case

@patch('xml.etree.ElementTree.parse')
def test_count_flows_and_components_parse_error(mock_et_parse, caplog):
    """Test count_flows_and_components with an ET.ParseError."""
    mock_et_parse.side_effect = ET.ParseError("mocked xml parse error")
    
    counts, _ = count_flows_and_components("dummy.xml")
    
    assert counts == {'flows': 0, 'sub_flows': 0, 'components': 0}
    assert any(
        "Error parsing XML file: dummy.xml - mocked xml parse error" in record.message
        for record in caplog.records if record.levelname == "ERROR"
    )

@patch('xml.etree.ElementTree.parse')
def test_count_flows_and_components_file_not_found(mock_et_parse, caplog):
    """Test count_flows_and_components with FileNotFoundError."""
    mock_et_parse.side_effect = FileNotFoundError("mocked file not found")
    
    counts, _ = count_flows_and_components("dummy.xml")
    
    assert counts == {'flows': 0, 'sub_flows': 0, 'components': 0}
    # Test that the second part of the tuple (invalid_flow_names) is empty
    # This part of the test might need adjustment based on actual return value of count_flows_and_components
    # For now, let's assume it returns ({counts}, []) when an error occurs before processing names
    # The function count_flows_and_components was modified to return counts, [] on error
    result_counts, invalid_names = count_flows_and_components("dummy.xml")
    assert result_counts == {'flows': 0, 'sub_flows': 0, 'components': 0}
    assert invalid_names == []
    assert any(
        "XML file not found: dummy.xml" in record.message
        for record in caplog.records if record.levelname == "ERROR"
    )

# Tests for is_camel_case (helper function, might be indirectly tested via validate_flow_name_camel_case)
def test_is_camel_case_basic():
    assert is_camel_case("camelCase") is True
    assert is_camel_case("PascalCase") is True
    assert is_camel_case("word") is True
    assert is_camel_case("anotherWord") is True
    assert is_camel_case("flow1") is True # Assuming numbers are allowed
    assert is_camel_case("f") is True # Single character
    assert is_camel_case("") is True # Empty string

    assert is_camel_case("under_score") is False
    assert is_camel_case("hyphen-ated") is False
    assert is_camel_case("ALLCAPS") is False # Unless it's a single char like "A"
    assert is_camel_case("A") is True
    assert is_camel_case("endsWithALLCAPS") is True # This should be true by current rule
    assert is_camel_case("alllowercase") is True # Currently true, might need refinement for "multiWordAllLower"

    # Tests for leading backslash handling in is_camel_case
    assert is_camel_case(r"\validName") is True
    assert is_camel_case(r"\invalid_name") is False
    assert is_camel_case(r"\\multipleSlashes") is False # after stripping one, '\multipleSlashes' remains
    assert is_camel_case(r"\ALLCAPS") is False
    assert is_camel_case("\\") is True # becomes "", which is True
    assert is_camel_case(r"\a") is True # becomes "a", which is True
    assert is_camel_case(r"validNameWith\internalSlash") is False # internal slashes are not allowed by default

# 3. Tests for validate_flow_name_camel_case(flow_name)
@pytest.mark.parametrize("flow_name, expected", [
    # Valid names
    ("validFlowName", True),
    ("anotherValidFlow", True),
    ("flow", True),
    ("f", True),
    ("flowName1", True),
    ("flowNameWithNumber123", True),
    ("PascalCaseName", True), # PascalCase is acceptable by is_camel_case
    ("verbNoun", True),

    # Invalid names (basic camel case rules)
    ("invalid_flow_name", False),
    ("invalid-flow-name", False),
    ("InvalidFlowName_with_error", False),
    ("ALLUPPERCASE", False), # Should be false unless it's a single char
    # ("alllowercaseformultiwords", False), # is_camel_case currently allows this, hard to distinguish from single "word"

    # Ignored flow names (substring check on original name)
    ("flow-main-test", True), # Contains "-main"
    ("my-console-flow", True), # Contains "-console"
    ("abc-xyz-integrationservices-main", True), # Contains "-main"
    (f"flow{IGNORED_FLOW_NAME_SUBSTRINGS[0]}", True),
    (f"flow{IGNORED_FLOW_NAME_SUBSTRINGS[1]}", True),


    # Rule: Text before the first ":" (after HTTP verb processing)
    ("flowNameBeforeColon:someSuffix", True),
    ("invalid_name_before_colon:suffix", False),
    ("ALLCAPSBEFORE:suffix", False),
    # The following is tricky: if "flow-main" is the part to validate, it's False.
    # But if the original name "flow-main:suffix" is checked for IGNORED_FLOW_NAME_SUBSTRINGS, "-main" is found.
    # The IGNORED_FLOW_NAME_SUBSTRINGS check happens first on the *original* name.
    (f"flow{IGNORED_FLOW_NAME_SUBSTRINGS[0]}:suffix", True), # Original name "flow-main:suffix" contains "-main" -> True
    ("validName:'\"", True), # Valid name before colon, colon itself is just a separator

    # Rule: Handling quotes ( "text between final "" ... " )
    ('"quotedFlowName"', True),
    ("'singleQuotedFlowName'", True),
    ('"invalid_quoted_name"', False),
    ("invalid_unclosed_quote", False), # This will be treated as part of the name
    ('""', True), # Empty string inside quotes, is_camel_case("") is True
    ('"A"', True), # Single char in quotes
    ('"ALLCAPS"', False), # All caps in quotes

    # Rule: Mime type exceptions
    ("application/json", True), # Exact mime type
    (COMMON_MIME_TYPES[0], True),
    ("text/csv", True),
    ("application/xml:config", True), # Mime type before colon
    ('"application/json":config', True), # Quoted mime type before colon
    ("notAMimeType", True), # Should be valid camel case
    ("invalid-mime/type-format", False), # Invalid due to hyphen if not in COMMON_MIME_TYPES

    # Combinations
    ('"validFlowNameBeforeColon":suffix', True),
    ("'invalid_name_also_quoted:suffix'", False),
    (f'"{IGNORED_FLOW_NAME_SUBSTRINGS[0]}":suffix', True),
    ("get:/customer", True), # "get" is valid by is_camel_case
    ("post:/order:createOrder", True), # "post" is valid
    ("put:/product/productId", True), # "put" is valid
    ("api/v1/users", True), # "api/v1/users" becomes "api/v1/users", which is_camel_case allows.
                            # If path segments should be camel cased, the rule needs to be more specific.
                            # Current rule for ":" means only part before first colon.
                            # Here, `is_camel_case` would fail if it has slashes and we want to disallow slashes.
                            # The `is_camel_case` allows anything not `_` or `-` or `ALLCAPS`.
                            # This implies "api/v1/users" is seen as a single "word".
                            # This might need clarification on how paths are handled.
                            # Let's assume for now that if it's not explicitly an ignored name or mime type,
                            # the remaining string after processing colons/quotes must pass is_camel_case.
                            # is_camel_case("api/v1/users") -> True because no _ or -
    ("path-like-name", False), # Fails due to hyphens
    ("path_like_name", False), # Fails due to underscore

    # Edge cases
    ("", True), # Empty string is considered valid by default by is_camel_case
    (":", True), # Becomes "", which is true
    ('":"', True), # Becomes "", which is true
    ('":suffix"', False), # Becomes ":suffix" if outer quotes are stripped, then "" before colon.
                         # current logic: name_to_validate = '":suffix"'. split by ':' -> '""'. validate '""' -> True
    ('name:"suffix"', True), # name_to_validate = "name". Valid.

    # New test cases for HTTP Verb Prefixes
    ("get:activeEmployees", True),
    ("post:createOrder:order-config", True), # createOrder is valid
    ("put:update_User:user-config", False), # update_User is invalid
    ("delete:removeResource:some-details", True), # removeResource is valid

    # New test cases for Suffixes
    ("activeEmployees:some-config-suffix", True),
    ("processData:another:config:here", True), # processData is valid
    ("invalid_Name:config:suffix", False),
    ("flowNameWithMultiple:Suffixes:LikeThis", True), # flowNameWithMultiple is valid

    # New test cases for Leading Backslashes
    # `validate_flow_name_camel_case` rule: `if "\\" in name_to_validate: return True`
    (r"\activeEmployees", True),
    (r"\processData:config", True),
    (r"\invalid_name:config", True), # This will be True due to the '\' rule in validate_flow_name_camel_case
    (r"get:\validFlow:config", True),
    (r"post:\invalid_Flow:config", True), # This will be True due to the '\' rule
    (r"get:\\doubleSlashFlow:config", True), # This will be True due to the '\' rule

    # New test cases for Combinations
    (r"get:\activeEmployees:hr-config", True), # Contains '\', so True
    ("post:process_Data:main-config", False), # process_Data is invalid, no '\' in "process_Data"

    # Original examples from the issue description - now anonymized
    # These will all be True if they contain '\' after prefix/suffix stripping by validate_flow_name_camel_case
    # Assuming the '\' is part of the name_to_validate:
    (r'get:\activeEmployees:sample-integrationservices-config', True),
    (r'get:\terminatedEmployees:sample-integrationservices-config', True),
    (r'get:\activeEmployeesfromDW:sample-integrationservices-config', True),
    (r'get:\activeEmployeesfromLdap:sample-integrationservices-config', True),
    (r'get:\sampleEmployees:sample-integrationservices-config', True),
    (r'get:\testEmployees:sample-integrationservices-config', True),
    (r'get:\terminatedEmployeesfromDW:sample-integrationservices-config', True),
    (r'get:\terminatedEmployeesfromLdap:sample-integrationservices-config', True),
    (r'get:\mockEmployees:sample-integrationservices-config', True),
    (r'get:\leaveBalance:sample-integrationservices-config', True),
    (r'get:\leaveBalanceFromDWH:sample-integrationservices-config', True),
    (r'get:\sampleData:sample-integrationservices-config', True),

    # Ensure IGNORED_FLOW_NAME_SUBSTRINGS still work correctly
    ("flowName-main", True), # Original name contains "-main"
    ("flowName-console", True),
    # If an ignored substring is part of the name *after* prefix/suffix stripping, it's not caught by the initial check.
    # The initial check is `if any(sub in flow_name for sub in IGNORED_FLOW_NAME_SUBSTRINGS):`
    ("get:flow-main-segment:config", False), # "flow-main-segment" is extracted. It contains "-main". is_camel_case("flow-main-segment") is False.
    ("flow-main-segment:config", False), # "flow-main-segment" is extracted. is_camel_case("flow-main-segment") is False.

    # Test cases where the part to validate itself might be a mime type or special string
    ("get:application/json:myapi-config", True), # "application/json" is extracted, which is in COMMON_MIME_TYPES
    ("post:text/plain:logging-config", True),   # "text/plain" is extracted, in COMMON_MIME_TYPES
    ("update:\"quotedName\":config", True),       # "\"quotedName\"" extracted, then "quotedName" validated
    ("verb:\"invalid_Name\":config", False),    # "\"invalid_Name\"" extracted, then "invalid_Name" validated

    # Test cases ensuring prefix/suffix stripping doesn't make invalid names valid
    ("get:invalid_NamePart:config", False),
    ("invalid_NamePart:suffix", False),
    (r"get:\invalid_NamePart:config", False),

    # What if the "actual name" part is empty after stripping?
    ("get::config", True), # name_to_validate becomes "", which is_camel_case returns True for.
    ("::config", True),    # name_to_validate becomes "", which is_camel_case returns True for.
    (r"get:\:config", True),# name_to_validate becomes "\", is_camel_case gets "\", becomes "", returns True.
    (r"\:config", True),   # name_to_validate becomes "\", is_camel_case gets "\", becomes "", returns True.
])
def test_validate_flow_name_camel_case(flow_name, expected, mock_logger_fixture):
    assert validate_flow_name_camel_case(flow_name) == expected

# 4. Updated Tests for count_flows_and_components and validate_flows_in_package
# These tests need to be aware that count_flows_and_components now returns a tuple (counts, invalid_names_list)

@patch('xml.etree.ElementTree.parse')
@patch('mule_validator.flow_validator.validate_flow_name_camel_case') # Mock the validator
def test_count_flows_and_components_with_name_validation(mock_validate_name, mock_et_parse):
    mock_flow_el1 = MagicMock()
    mock_flow_el1.get.return_value = "validFlowName"
    mock_flow_el1.__len__.return_value = 1 # 1 component

    mock_flow_el2 = MagicMock()
    mock_flow_el2.get.return_value = "invalid_flow_Name"
    mock_flow_el2.__len__.return_value = 1

    mock_sub_flow_el = MagicMock()
    mock_sub_flow_el.get.return_value = "validSubFlow" # Assume subflows are also validated
    mock_sub_flow_el.__len__.return_value = 1

    mock_root = MagicMock()
    mock_root.findall(f'.//{{{MULE_CORE_NAMESPACE_URI}}}flow').return_value = [mock_flow_el1, mock_flow_el2]
    mock_root.findall(f'.//{{{MULE_CORE_NAMESPACE_URI}}}sub-flow').return_value = [mock_sub_flow_el]

    mock_tree = MagicMock()
    mock_tree.getroot.return_value = mock_root
    mock_et_parse.return_value = mock_tree

    # Define side effects for the validator
    mock_validate_name.side_effect = lambda name: name == "validFlowName" or name == "validSubFlow"

    counts, invalid_names = count_flows_and_components("dummy.xml")

    assert counts['flows'] == 2
    assert counts['sub_flows'] == 1
    assert counts['components'] == 3
    assert "invalid_flow_Name" in invalid_names
    assert "subflow:validSubFlow" not in invalid_names # validSubFlow should pass
    # Check if subflow name validation occurred as expected
    # If "validSubFlow" was invalid, it would be "subflow:validSubFlow" in invalid_names

    # Check calls to validate_flow_name_camel_case
    expected_calls = [call("validFlowName"), call("invalid_flow_Name"), call("validSubFlow")]
    mock_validate_name.assert_has_calls(expected_calls, any_order=False) # Order of finding elements

@patch('xml.etree.ElementTree.parse')
def test_count_flows_and_components_parse_error_returns_empty_invalid_list(mock_et_parse, caplog):
    """Test count_flows_and_components with an ET.ParseError returns empty invalid_names list."""
    mock_et_parse.side_effect = ET.ParseError("mocked xml parse error")

    counts, invalid_names = count_flows_and_components("dummy.xml")

    assert counts == {'flows': 0, 'sub_flows': 0, 'components': 0}
    assert invalid_names == [] # Important: should return empty list for invalid names on error
    assert any("Error parsing XML file: dummy.xml - mocked xml parse error" in record.message for record in caplog.records)


# 2. Tests for validate_flows_in_package(...)

@patch('mule_validator.flow_validator.count_flows_and_components')
@patch('os.walk')
@patch('os.path.isdir')
def test_validate_flows_src_main_mule_not_found(mock_isdir, mock_os_walk, mock_count_flows_func, caplog): # Renamed mock_count_flows
    """Test validate_flows_in_package when src/main/mule directory does not exist."""
    package_path = "dummy_package"
    expected_mule_path = os.path.join(package_path, 'src', 'main', 'mule')
    mock_isdir.return_value = False
    
    with pytest.raises(FileNotFoundError) as excinfo:
        validate_flows_in_package(package_path)
    
    assert str(excinfo.value) == f"Mule source directory does not exist: {expected_mule_path}"
    mock_isdir.assert_called_once_with(expected_mule_path)
    mock_os_walk.assert_not_called()
    mock_count_flows_func.assert_not_called() # Use renamed mock
    assert any(
        f"Mule source directory does not exist: {expected_mule_path}" in record.message
        for record in caplog.records if record.levelname == "ERROR"
    )

@patch('mule_validator.flow_validator.count_flows_and_components')
@patch('os.walk')
@patch('os.path.isdir')
def test_validate_flows_no_xml_files_found(mock_isdir, mock_os_walk, mock_count_flows_func, caplog): # Renamed mock_count_flows
    """Test validate_flows_in_package when no XML files are found in src/main/mule."""
    package_path = "dummy_package"
    expected_mule_path = os.path.join(package_path, 'src', 'main', 'mule')
    
    mock_isdir.return_value = True
    mock_os_walk.return_value = [
        (expected_mule_path, [], ['not_an_xml.txt', 'another_file.json']) # No XML files
    ]
    
    results = validate_flows_in_package(package_path)
    
    assert results['total_counts'] == {'flows': 0, 'sub_flows': 0, 'components': 0}
    assert results['flows_ok'] is True
    assert results['sub_flows_ok'] is True
    assert results['components_ok'] is True
    assert results['flow_names_camel_case_ok'] is True # No invalid names as no files processed
    assert results['invalid_flow_names'] == []
    mock_count_flows_func.assert_not_called() # Use renamed mock
    assert any(
        f"No XML files found in {expected_mule_path}. Counts will be zero." in record.message
        for record in caplog.records if record.levelname == "WARNING"
    )

@patch('mule_validator.flow_validator.count_flows_and_components')
@patch('os.walk')
@patch('os.path.isdir')
def test_validate_flows_counts_within_limits_and_names_ok(mock_isdir, mock_os_walk, mock_count_flows_func): # Renamed mock_count_flows
    """Test validate_flows_in_package with counts within limits and valid flow names."""
    package_path = "dummy_package"
    expected_mule_path = os.path.join(package_path, 'src', 'main', 'mule')
    
    mock_isdir.return_value = True
    mock_os_walk.return_value = [
        (expected_mule_path, [], ['file1.xml', 'file2.xml'])
    ]
    mock_count_flows_func.side_effect = [
        ({'flows': 5, 'sub_flows': 2, 'components': 20}, []), # file1.xml, no invalid names
        ({'flows': 5, 'sub_flows': 3, 'components': 30}, [])  # file2.xml, no invalid names
    ]
    
    results = validate_flows_in_package(package_path)
    
    assert results['total_counts'] == {'flows': 10, 'sub_flows': 5, 'components': 50}
    assert results['flows_ok'] is True
    assert results['sub_flows_ok'] is True
    assert results['components_ok'] is True
    assert results['flow_names_camel_case_ok'] is True
    assert results['invalid_flow_names'] == []
    
    expected_calls = [
        call(os.path.join(expected_mule_path, 'file1.xml')),
        call(os.path.join(expected_mule_path, 'file2.xml'))
    ]
    mock_count_flows_func.assert_has_calls(expected_calls, any_order=False)

@patch('mule_validator.flow_validator.count_flows_and_components')
@patch('os.walk')
@patch('os.path.isdir')
def test_validate_flows_with_invalid_names(mock_isdir, mock_os_walk, mock_count_flows_func, caplog): # Renamed mock_count_flows
    """Test validate_flows_in_package with some invalid flow names."""
    package_path = "dummy_package"
    mock_isdir.return_value = True
    mock_os_walk.return_value = [
        (os.path.join(package_path, 'src', 'main', 'mule'), [], ['file1.xml', 'file2.xml'])
    ]
    mock_count_flows_func.side_effect = [
        ({'flows': 1, 'sub_flows': 0, 'components': 5}, ["invalid_Name1"]),
        ({'flows': 1, 'sub_flows': 0, 'components': 5}, ["another-InvalidName"])
    ]

    results = validate_flows_in_package(package_path)

    assert results['total_counts'] == {'flows': 2, 'sub_flows': 0, 'components': 10}
    assert results['flows_ok'] is True # Assuming counts are within limits
    assert results['flow_names_camel_case_ok'] is False
    assert results['invalid_flow_names'] == ["invalid_Name1", "another-InvalidName"]
    assert any("Found invalid flow names" in record.message for record in caplog.records if record.levelname == "WARNING")

@patch('mule_validator.flow_validator.count_flows_and_components')
@patch('os.walk')
@patch('os.path.isdir')
def test_validate_flows_exceed_one_limit_and_names_ok(mock_isdir, mock_os_walk, mock_count_flows_func, caplog): # Renamed mock_count_flows
    """Test validate_flows_in_package when flow count exceeds limit, names are ok."""
    package_path = "dummy_package"
    mock_isdir.return_value = True
    mock_os_walk.return_value = [
        (os.path.join(package_path, 'src', 'main', 'mule'), [], ['file1.xml'])
    ]
    mock_count_flows_func.return_value = ({'flows': 150, 'sub_flows': 10, 'components': 100}, []) # No invalid names
    
    results = validate_flows_in_package(package_path, max_flows=100, max_sub_flows=50, max_components=500)
    
    assert results['total_counts']['flows'] == 150
    assert results['flows_ok'] is False
    assert results['sub_flows_ok'] is True
    assert results['components_ok'] is True
    assert results['flow_names_camel_case_ok'] is True # Names are fine
    assert results['invalid_flow_names'] == []
    assert any("Flow count 150 exceeds limit of 100" in record.message for record in caplog.records)

@patch('mule_validator.flow_validator.count_flows_and_components')
@patch('os.walk')
@patch('os.path.isdir')
def test_validate_flows_exceed_multiple_limits_and_invalid_names(mock_isdir, mock_os_walk, mock_count_flows_func, caplog): # Renamed
    """Test validate_flows_in_package with multiple limits exceeded and invalid names."""
    package_path = "dummy_package"
    mock_isdir.return_value = True
    mock_os_walk.return_value = [
        (os.path.join(package_path, 'src', 'main', 'mule'), [], ['file1.xml'])
    ]
    mock_count_flows_func.return_value = ({'flows': 150, 'sub_flows': 10, 'components': 600}, ["bad_name"])
    
    results = validate_flows_in_package(package_path, max_flows=100, max_sub_flows=50, max_components=500)
    
    assert results['flows_ok'] is False
    assert results['sub_flows_ok'] is True # Assuming sub_flows is ok
    assert results['components_ok'] is False
    assert results['flow_names_camel_case_ok'] is False
    assert results['invalid_flow_names'] == ["bad_name"]
    assert any("Flow count 150 exceeds limit of 100" in record.message for record in caplog.records)
    assert any("Component count 600 exceeds limit of 500" in record.message for record in caplog.records)
    assert any("Found invalid flow names" in record.message for record in caplog.records)


@patch('mule_validator.flow_validator.count_flows_and_components')
@patch('os.walk')
@patch('os.path.isdir')
def test_validate_flows_custom_limits_and_names_ok(mock_isdir, mock_os_walk, mock_count_flows_func): # Renamed
    """Test validate_flows_in_package with custom limits and ok names."""
    package_path = "dummy_package"
    mock_isdir.return_value = True
    mock_os_walk.return_value = [
        (os.path.join(package_path, 'src', 'main', 'mule'), [], ['file1.xml'])
    ]
    mock_count_flows_func.return_value = ({'flows': 110, 'sub_flows': 55, 'components': 550}, [])
    
    custom_max_flows = 120
    custom_max_sub_flows = 60
    custom_max_components = 600
    
    results = validate_flows_in_package(
        package_path, 
        max_flows=custom_max_flows, 
        max_sub_flows=custom_max_sub_flows, 
        max_components=custom_max_components
    )
    
    assert results['total_counts'] == {'flows': 110, 'sub_flows': 55, 'components': 550}
    assert results['flows_ok'] is True
    assert results['sub_flows_ok'] is True
    assert results['components_ok'] is True
    assert results['flow_names_camel_case_ok'] is True
    assert results['invalid_flow_names'] == []
    assert results['max_flows_limit'] == custom_max_flows
    assert results['max_sub_flows_limit'] == custom_max_sub_flows
    assert results['max_components_limit'] == custom_max_components

@patch('mule_validator.flow_validator.count_flows_and_components')
@patch('os.walk')
@patch('os.path.isdir')
def test_validate_flows_mixed_counts_and_names_from_files(mock_isdir, mock_os_walk, mock_count_flows_func): # Renamed
    """Test summing counts and aggregating invalid names correctly."""
    package_path = "dummy_package"
    expected_mule_path = os.path.join(package_path, 'src', 'main', 'mule')
    
    mock_isdir.return_value = True
    mock_os_walk.return_value = [
        (expected_mule_path, [], ['file_empty.xml', 'file_with_flows.xml', 'file_zero_comps.xml', 'file_bad_names.xml'])
    ]
    mock_count_flows_func.side_effect = [
        ({'flows': 0, 'sub_flows': 0, 'components': 0}, []),
        ({'flows': 10, 'sub_flows': 2, 'components': 30}, ["badNameInSecondFile"]),
        ({'flows': 1, 'sub_flows': 0, 'components': 0}, []),
        ({'flows': 2, 'sub_flows': 1, 'components': 5}, ["anotherBad", "oneMore_bad"])
    ]
    
    results = validate_flows_in_package(package_path) # Using default limits
    
    assert results['total_counts'] == {'flows': 13, 'sub_flows': 3, 'components': 35}
    assert results['flows_ok'] is True # Assuming counts are within limits
    assert results['sub_flows_ok'] is True
    assert results['components_ok'] is True
    assert results['flow_names_camel_case_ok'] is False
    assert results['invalid_flow_names'] == ["badNameInSecondFile", "anotherBad", "oneMore_bad"]

    expected_calls = [
        call(os.path.join(expected_mule_path, 'file_empty.xml')),
        call(os.path.join(expected_mule_path, 'file_with_flows.xml')),
        call(os.path.join(expected_mule_path, 'file_zero_comps.xml')),
        call(os.path.join(expected_mule_path, 'file_bad_names.xml'))
    ]
    mock_count_flows_func.assert_has_calls(expected_calls, any_order=False)
