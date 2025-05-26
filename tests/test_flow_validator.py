import pytest
import os
import xml.etree.ElementTree as ET
from unittest.mock import patch, MagicMock, call

from mule_validator.flow_validator import (
    count_flows_and_components,
    validate_flows_in_package,
    MULE_CORE_NAMESPACE_URI  # For constructing mock XML if needed, or verifying usage
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
        
        counts = count_flows_and_components("dummy.xml")
        
        assert counts['flows'] == exp_f, f"Test '{name}' failed for flows"
        assert counts['sub_flows'] == exp_sf, f"Test '{name}' failed for sub-flows"
        assert counts['components'] == exp_c, f"Test '{name}' failed for components"
        mock_et_parse.assert_called_with("dummy.xml") # Called for each case

@patch('xml.etree.ElementTree.parse')
def test_count_flows_and_components_parse_error(mock_et_parse, caplog):
    """Test count_flows_and_components with an ET.ParseError."""
    mock_et_parse.side_effect = ET.ParseError("mocked xml parse error")
    
    counts = count_flows_and_components("dummy.xml")
    
    assert counts == {'flows': 0, 'sub_flows': 0, 'components': 0}
    assert any(
        "Error parsing XML file: dummy.xml - mocked xml parse error" in record.message
        for record in caplog.records if record.levelname == "ERROR"
    )

@patch('xml.etree.ElementTree.parse')
def test_count_flows_and_components_file_not_found(mock_et_parse, caplog):
    """Test count_flows_and_components with FileNotFoundError."""
    mock_et_parse.side_effect = FileNotFoundError("mocked file not found")
    
    counts = count_flows_and_components("dummy.xml")
    
    assert counts == {'flows': 0, 'sub_flows': 0, 'components': 0}
    assert any(
        "XML file not found: dummy.xml" in record.message # Message from the refactored code
        for record in caplog.records if record.levelname == "ERROR"
    )


# 2. Tests for validate_flows_in_package(...)

@patch('mule_validator.flow_validator.count_flows_and_components')
@patch('os.walk')
@patch('os.path.isdir')
def test_validate_flows_src_main_mule_not_found(mock_isdir, mock_os_walk, mock_count_flows, caplog):
    """Test validate_flows_in_package when src/main/mule directory does not exist."""
    package_path = "dummy_package"
    expected_mule_path = os.path.join(package_path, 'src', 'main', 'mule')
    mock_isdir.return_value = False
    
    with pytest.raises(FileNotFoundError) as excinfo:
        validate_flows_in_package(package_path)
    
    assert str(excinfo.value) == f"Mule source directory does not exist: {expected_mule_path}"
    mock_isdir.assert_called_once_with(expected_mule_path)
    mock_os_walk.assert_not_called()
    mock_count_flows.assert_not_called()
    assert any(
        f"Mule source directory does not exist: {expected_mule_path}" in record.message
        for record in caplog.records if record.levelname == "ERROR"
    )

@patch('mule_validator.flow_validator.count_flows_and_components')
@patch('os.walk')
@patch('os.path.isdir')
def test_validate_flows_no_xml_files_found(mock_isdir, mock_os_walk, mock_count_flows, caplog):
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
    mock_count_flows.assert_not_called() # No XML files to process
    assert any(
        f"No XML files found in {expected_mule_path}. Counts will be zero." in record.message
        for record in caplog.records if record.levelname == "WARNING"
    )

@patch('mule_validator.flow_validator.count_flows_and_components')
@patch('os.walk')
@patch('os.path.isdir')
def test_validate_flows_counts_within_limits(mock_isdir, mock_os_walk, mock_count_flows):
    """Test validate_flows_in_package with counts within default limits."""
    package_path = "dummy_package"
    expected_mule_path = os.path.join(package_path, 'src', 'main', 'mule')
    
    mock_isdir.return_value = True
    mock_os_walk.return_value = [
        (expected_mule_path, [], ['file1.xml', 'file2.xml'])
    ]
    # Let each file contribute some counts
    mock_count_flows.side_effect = [
        {'flows': 5, 'sub_flows': 2, 'components': 20}, # for file1.xml
        {'flows': 5, 'sub_flows': 3, 'components': 30}  # for file2.xml
    ]
    
    results = validate_flows_in_package(package_path) # Using default limits
    
    assert results['total_counts'] == {'flows': 10, 'sub_flows': 5, 'components': 50}
    assert results['flows_ok'] is True
    assert results['sub_flows_ok'] is True
    assert results['components_ok'] is True
    assert results['max_flows_limit'] == 100 # Default
    assert results['max_sub_flows_limit'] == 50 # Default
    assert results['max_components_limit'] == 500 # Default
    
    expected_calls = [
        call(os.path.join(expected_mule_path, 'file1.xml')),
        call(os.path.join(expected_mule_path, 'file2.xml'))
    ]
    mock_count_flows.assert_has_calls(expected_calls, any_order=False) # Order matters with side_effect list

@patch('mule_validator.flow_validator.count_flows_and_components')
@patch('os.walk')
@patch('os.path.isdir')
def test_validate_flows_exceed_one_limit(mock_isdir, mock_os_walk, mock_count_flows, caplog):
    """Test validate_flows_in_package when flow count exceeds the limit."""
    package_path = "dummy_package"
    mock_isdir.return_value = True
    mock_os_walk.return_value = [
        (os.path.join(package_path, 'src', 'main', 'mule'), [], ['file1.xml'])
    ]
    mock_count_flows.return_value = {'flows': 150, 'sub_flows': 10, 'components': 100}
    
    results = validate_flows_in_package(package_path, max_flows=100, max_sub_flows=50, max_components=500)
    
    assert results['total_counts']['flows'] == 150
    assert results['flows_ok'] is False
    assert results['sub_flows_ok'] is True
    assert results['components_ok'] is True
    assert any(
        "Flow count 150 exceeds limit of 100" in record.message
        for record in caplog.records if record.levelname == "WARNING"
    )

@patch('mule_validator.flow_validator.count_flows_and_components')
@patch('os.walk')
@patch('os.path.isdir')
def test_validate_flows_exceed_multiple_limits(mock_isdir, mock_os_walk, mock_count_flows, caplog):
    """Test validate_flows_in_package when multiple counts exceed limits."""
    package_path = "dummy_package"
    mock_isdir.return_value = True
    mock_os_walk.return_value = [
        (os.path.join(package_path, 'src', 'main', 'mule'), [], ['file1.xml'])
    ]
    mock_count_flows.return_value = {'flows': 150, 'sub_flows': 10, 'components': 600}
    
    results = validate_flows_in_package(package_path, max_flows=100, max_sub_flows=50, max_components=500)
    
    assert results['flows_ok'] is False
    assert results['sub_flows_ok'] is True
    assert results['components_ok'] is False
    assert any("Flow count 150 exceeds limit of 100" in record.message for record in caplog.records)
    assert any("Component count 600 exceeds limit of 500" in record.message for record in caplog.records)

@patch('mule_validator.flow_validator.count_flows_and_components')
@patch('os.walk')
@patch('os.path.isdir')
def test_validate_flows_custom_limits(mock_isdir, mock_os_walk, mock_count_flows):
    """Test validate_flows_in_package with custom limits provided."""
    package_path = "dummy_package"
    mock_isdir.return_value = True
    mock_os_walk.return_value = [
        (os.path.join(package_path, 'src', 'main', 'mule'), [], ['file1.xml'])
    ]
    # Counts that would fail default limits but pass custom limits
    mock_count_flows.return_value = {'flows': 110, 'sub_flows': 55, 'components': 550} 
    
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
    assert results['max_flows_limit'] == custom_max_flows
    assert results['max_sub_flows_limit'] == custom_max_sub_flows
    assert results['max_components_limit'] == custom_max_components

@patch('mule_validator.flow_validator.count_flows_and_components')
@patch('os.walk')
@patch('os.path.isdir')
def test_validate_flows_mixed_counts_from_files(mock_isdir, mock_os_walk, mock_count_flows):
    """Test summing counts correctly when some files have zero counts."""
    package_path = "dummy_package"
    expected_mule_path = os.path.join(package_path, 'src', 'main', 'mule')
    
    mock_isdir.return_value = True
    mock_os_walk.return_value = [
        (expected_mule_path, [], ['file_empty.xml', 'file_with_flows.xml', 'file_zero_comps.xml'])
    ]
    mock_count_flows.side_effect = [
        {'flows': 0, 'sub_flows': 0, 'components': 0},      # for file_empty.xml
        {'flows': 10, 'sub_flows': 2, 'components': 30},    # for file_with_flows.xml
        {'flows': 1, 'sub_flows': 0, 'components': 0}       # for file_zero_comps.xml
    ]
    
    results = validate_flows_in_package(package_path) # Using default limits
    
    assert results['total_counts'] == {'flows': 11, 'sub_flows': 2, 'components': 30}
    assert results['flows_ok'] is True
    assert results['sub_flows_ok'] is True
    assert results['components_ok'] is True

    expected_calls = [
        call(os.path.join(expected_mule_path, 'file_empty.xml')),
        call(os.path.join(expected_mule_path, 'file_with_flows.xml')),
        call(os.path.join(expected_mule_path, 'file_zero_comps.xml'))
    ]
    mock_count_flows.assert_has_calls(expected_calls, any_order=False)
