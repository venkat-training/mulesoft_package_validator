import pytest
import os
import xml.etree.ElementTree as ET
from unittest.mock import patch, MagicMock, call

from mule_validator.api_validator import (
    validate_api_spec_and_flows,
    API_SPECS_PATH_NAME,
    SRC_MAIN_MULE_PATH_NAME,
    API_SPEC_EXTENSIONS,
    API_DEFINITION_FLOW_NAME_MARKER,
    MULE_CORE_NAMESPACE_URI
)

# Mock the logger for all tests in this module
@pytest.fixture(autouse=True)
def mock_logger_fixture():
    with patch('mule_validator.api_validator.logger', MagicMock()) as mock_log:
        yield mock_log

# Helper function to create a mock XML tree for ET.parse
def create_mock_xml_tree(flow_names=None):
    if flow_names is None:
        flow_names = []
    
    mock_root = MagicMock()
    mock_flows = []
    for name in flow_names:
        mock_flow = MagicMock()
        mock_flow.get.return_value = name # Mock .get('name', '').lower()
        mock_flows.append(mock_flow)
    
    # Mock findall to return these flows when called with './/mule:flow' and correct namespaces
    # Need to be careful with how findall is called in the main code (with or without namespaces arg)
    # The refactored code uses: xml_root.findall('.//mule:flow', namespaces={'mule': MULE_CORE_NAMESPACE_URI})
    mock_root.findall.return_value = mock_flows
    
    mock_tree = MagicMock()
    mock_tree.getroot.return_value = mock_root
    return mock_tree

# Test Scenarios

@patch('xml.etree.ElementTree.parse')
@patch('os.walk')
@patch('os.path.isdir') # Also mock os.path.isdir as it's used to check path existence
def test_scenario1_spec_and_def_flow_found(mock_isdir, mock_os_walk, mock_et_parse):
    """Scenario 1: Both API Spec and Definition Flow Found."""
    mock_isdir.return_value = True # All paths exist
    dummy_package_path = "dummy_package"
    
    # Configure os.walk for API_SPECS_PATH_NAME
    api_specs_full_path = os.path.join(dummy_package_path, API_SPECS_PATH_NAME)
    # Configure os.walk for SRC_MAIN_MULE_PATH_NAME
    src_main_mule_full_path = os.path.join(dummy_package_path, SRC_MAIN_MULE_PATH_NAME)

    def os_walk_side_effect(path):
        if path == api_specs_full_path:
            return [
                (api_specs_full_path, [], ['api.raml', 'other.txt'])
            ]
        elif path == src_main_mule_full_path:
            return [
                (src_main_mule_full_path, [], ['flow1.xml', 'api_flow.xml'])
            ]
        return [] # Default for other paths
    mock_os_walk.side_effect = os_walk_side_effect

    # Configure ET.parse
    def et_parse_side_effect(file_path):
        if file_path == os.path.join(src_main_mule_full_path, 'flow1.xml'):
            return create_mock_xml_tree(flow_names=['normalFlow'])
        elif file_path == os.path.join(src_main_mule_full_path, 'api_flow.xml'):
            return create_mock_xml_tree(flow_names=[f'get:\\p{API_DEFINITION_FLOW_NAME_MARKER}\\something:api-config'])
        raise ValueError(f"ET.parse called with unexpected path: {file_path}")
    mock_et_parse.side_effect = et_parse_side_effect

    results = validate_api_spec_and_flows(dummy_package_path)

    assert results['api_spec_found'] is True
    assert results['api_definition_flow_found'] is True
    assert os.path.join(api_specs_full_path, 'api.raml') in results['api_spec_files']
    assert os.path.join(src_main_mule_full_path, 'api_flow.xml') in results['api_definition_flows']


@patch('xml.etree.ElementTree.parse')
@patch('os.walk')
@patch('os.path.isdir')
def test_scenario2_no_api_spec_found(mock_isdir, mock_os_walk, mock_et_parse):
    """Scenario 2: No API Spec Found, but Definition Flow is Found."""
    mock_isdir.return_value = True
    dummy_package_path = "dummy_package"
    api_specs_full_path = os.path.join(dummy_package_path, API_SPECS_PATH_NAME)
    src_main_mule_full_path = os.path.join(dummy_package_path, SRC_MAIN_MULE_PATH_NAME)

    def os_walk_side_effect(path):
        if path == api_specs_full_path:
            return [
                (api_specs_full_path, [], ['other.txt']) # No spec files
            ]
        elif path == src_main_mule_full_path:
            return [
                (src_main_mule_full_path, [], ['api_flow.xml'])
            ]
        return []
    mock_os_walk.side_effect = os_walk_side_effect
    mock_et_parse.return_value = create_mock_xml_tree(flow_names=[f'get:\\p{API_DEFINITION_FLOW_NAME_MARKER}\\something'])

    results = validate_api_spec_and_flows(dummy_package_path)

    assert results['api_spec_found'] is False
    assert results['api_definition_flow_found'] is True
    assert results['api_spec_files'] == []


@patch('xml.etree.ElementTree.parse')
@patch('os.walk')
@patch('os.path.isdir')
def test_scenario3_no_api_definition_flow_found(mock_isdir, mock_os_walk, mock_et_parse):
    """Scenario 3: API Spec Found, but No Definition Flow is Found."""
    mock_isdir.return_value = True
    dummy_package_path = "dummy_package"
    api_specs_full_path = os.path.join(dummy_package_path, API_SPECS_PATH_NAME)
    src_main_mule_full_path = os.path.join(dummy_package_path, SRC_MAIN_MULE_PATH_NAME)
    
    def os_walk_side_effect(path):
        if path == api_specs_full_path:
            return [
                (api_specs_full_path, [], ['api.raml'])
            ]
        elif path == src_main_mule_full_path:
            return [
                (src_main_mule_full_path, [], ['flow1.xml', 'flow2.xml'])
            ]
        return []
    mock_os_walk.side_effect = os_walk_side_effect
    mock_et_parse.return_value = create_mock_xml_tree(flow_names=['normalFlow', 'anotherFlow']) # No API flows

    results = validate_api_spec_and_flows(dummy_package_path)

    assert results['api_spec_found'] is True
    assert results['api_definition_flow_found'] is False
    assert results['api_definition_flows'] == []


@patch('xml.etree.ElementTree.parse')
@patch('os.walk')
@patch('os.path.isdir')
def test_scenario4_neither_found(mock_isdir, mock_os_walk, mock_et_parse):
    """Scenario 4: Neither API Spec nor Definition Flow Found."""
    mock_isdir.return_value = True
    dummy_package_path = "dummy_package"
    api_specs_full_path = os.path.join(dummy_package_path, API_SPECS_PATH_NAME)
    src_main_mule_full_path = os.path.join(dummy_package_path, SRC_MAIN_MULE_PATH_NAME)

    def os_walk_side_effect(path):
        if path == api_specs_full_path:
            return [
                (api_specs_full_path, [], ['other.txt']) # No spec files
            ]
        elif path == src_main_mule_full_path:
            return [
                (src_main_mule_full_path, [], ['flow1.xml'])
            ]
        return []
    mock_os_walk.side_effect = os_walk_side_effect
    mock_et_parse.return_value = create_mock_xml_tree(flow_names=['normalFlow']) # No API flows

    results = validate_api_spec_and_flows(dummy_package_path)

    assert results['api_spec_found'] is False
    assert results['api_definition_flow_found'] is False
    assert results['api_spec_files'] == []
    assert results['api_definition_flows'] == []


@patch('xml.etree.ElementTree.parse') # Mock ET even if not directly used by spec part, for consistency
@patch('os.walk')
@patch('os.path.isdir')
def test_scenario5_multiple_spec_files(mock_isdir, mock_os_walk, mock_et_parse):
    """Scenario 5: Multiple Spec Files (RAML, YAML, JSON) Found."""
    mock_isdir.return_value = True
    dummy_package_path = "dummy_package"
    api_specs_full_path = os.path.join(dummy_package_path, API_SPECS_PATH_NAME)
    src_main_mule_full_path = os.path.join(dummy_package_path, SRC_MAIN_MULE_PATH_NAME)

    spec_files = ['api.raml', 'openapi.yaml', 'swagger.json', 'ignored.txt']
    expected_spec_files = [
        os.path.join(api_specs_full_path, 'api.raml'),
        os.path.join(api_specs_full_path, 'openapi.yaml'),
        os.path.join(api_specs_full_path, 'swagger.json')
    ]

    def os_walk_side_effect(path):
        if path == api_specs_full_path:
            return [
                (api_specs_full_path, [], spec_files)
            ]
        elif path == src_main_mule_full_path: # Assume no API flows for simplicity of this test
            return [
                (src_main_mule_full_path, [], ['flow.xml'])
            ]
        return []
    mock_os_walk.side_effect = os_walk_side_effect
    mock_et_parse.return_value = create_mock_xml_tree(flow_names=['normalFlow'])

    results = validate_api_spec_and_flows(dummy_package_path)

    assert results['api_spec_found'] is True
    assert len(results['api_spec_files']) == 3
    for f in expected_spec_files:
        assert f in results['api_spec_files']


@patch('xml.etree.ElementTree.parse')
@patch('os.walk')
@patch('os.path.isdir')
def test_scenario6_xml_parsing_error(mock_isdir, mock_os_walk, mock_et_parse, caplog):
    """Scenario 6: XML Parsing Error for one file during Definition Flow search."""
    mock_isdir.return_value = True
    dummy_package_path = "dummy_package"
    api_specs_full_path = os.path.join(dummy_package_path, API_SPECS_PATH_NAME) # Assume spec is found
    src_main_mule_full_path = os.path.join(dummy_package_path, SRC_MAIN_MULE_PATH_NAME)

    good_xml_path = os.path.join(src_main_mule_full_path, 'good.xml')
    bad_xml_path = os.path.join(src_main_mule_full_path, 'bad.xml')
    another_api_xml_path = os.path.join(src_main_mule_full_path, 'another_api.xml')

    def os_walk_side_effect(path):
        if path == api_specs_full_path:
            return [(api_specs_full_path, [], ['api.raml'])]
        elif path == src_main_mule_full_path:
            return [(src_main_mule_full_path, [], ['good.xml', 'bad.xml', 'another_api.xml'])]
        return []
    mock_os_walk.side_effect = os_walk_side_effect

    def et_parse_side_effect(file_path):
        if file_path == good_xml_path:
            return create_mock_xml_tree(flow_names=['normalFlow'])
        elif file_path == bad_xml_path:
            raise ET.ParseError("mocked XML parse error")
        elif file_path == another_api_xml_path:
            return create_mock_xml_tree(flow_names=[f'post:\\p{API_DEFINITION_FLOW_NAME_MARKER}\\v1:config'])
        raise ValueError(f"ET.parse called with unexpected path: {file_path}")
    mock_et_parse.side_effect = et_parse_side_effect

    results = validate_api_spec_and_flows(dummy_package_path)

    assert results['api_spec_found'] is True # From api.raml
    assert results['api_definition_flow_found'] is True # From another_api.xml
    assert another_api_xml_path in results['api_definition_flows']
    assert bad_xml_path not in results['api_definition_flows'] # Should not be added if parse fails
    
    assert any(
        f"Error parsing XML file: {bad_xml_path} - mocked XML parse error" in record.message
        for record in caplog.records if record.levelname == "ERROR"
    )

@patch('os.walk')
@patch('os.path.isdir')
def test_scenario7_target_directories_not_found(mock_isdir, mock_os_walk, caplog):
    """Scenario 7: Target directories for specs and/or Mule XMLs not found."""
    mock_isdir.return_value = False # Simulate both directories not existing
    dummy_package_path = "dummy_package"
    api_specs_full_path = os.path.join(dummy_package_path, API_SPECS_PATH_NAME)
    src_main_mule_full_path = os.path.join(dummy_package_path, SRC_MAIN_MULE_PATH_NAME)

    # os.walk will not even be called if os.path.isdir is False for the root scan paths.
    # The function logs a warning and proceeds.
    
    results = validate_api_spec_and_flows(dummy_package_path)

    assert results['api_spec_found'] is False
    assert results['api_definition_flow_found'] is False
    assert results['api_spec_files'] == []
    assert results['api_definition_flows'] == []

    assert any(
        f"API specification directory does not exist: {api_specs_full_path}" in record.message
        for record in caplog.records if record.levelname == "WARNING"
    )
    assert any(
        f"Mule XML directory does not exist: {src_main_mule_full_path}" in record.message
        for record in caplog.records if record.levelname == "WARNING"
    )
    # Also check for the summary logs
    assert any(
        f"No API specification files found in {api_specs_full_path}" in record.message
        for record in caplog.records if record.levelname == "WARNING"
    )
    assert any(
        f"No API definition flows found in XML files under {src_main_mule_full_path}" in record.message
        for record in caplog.records if record.levelname == "WARNING"
    )


@patch('xml.etree.ElementTree.parse')
@patch('os.walk')
@patch('os.path.isdir')
def test_scenario8_duplicate_api_definition_flow_prevention(mock_isdir, mock_os_walk, mock_et_parse):
    """Scenario 8: Ensure a file with multiple API flows is listed only once."""
    mock_isdir.return_value = True
    dummy_package_path = "dummy_package"
    src_main_mule_full_path = os.path.join(dummy_package_path, SRC_MAIN_MULE_PATH_NAME)
    api_specs_full_path = os.path.join(dummy_package_path, API_SPECS_PATH_NAME) # Assume no specs for simplicity

    # Single XML file that will contain multiple API-named flows
    single_api_xml_file = os.path.join(src_main_mule_full_path, 'multi_api_flow.xml')

    def os_walk_side_effect(path):
        if path == api_specs_full_path:
            return [] # No specs
        elif path == src_main_mule_full_path:
            return [
                (src_main_mule_full_path, [], ['multi_api_flow.xml'])
            ]
        return []
    mock_os_walk.side_effect = os_walk_side_effect

    # This XML tree will have two flows that match the API definition criteria
    mock_et_parse.return_value = create_mock_xml_tree(flow_names=[
        f'get:\\p{API_DEFINITION_FLOW_NAME_MARKER}\\resource1:config',
        f'post:\\p{API_DEFINITION_FLOW_NAME_MARKER}\\resource2:config'
    ])

    results = validate_api_spec_and_flows(dummy_package_path)

    assert results['api_definition_flow_found'] is True
    # The file path should only appear once in the list, even if multiple flows within it matched.
    assert len(results['api_definition_flows']) == 1
    assert single_api_xml_file in results['api_definition_flows']
    mock_et_parse.assert_called_once_with(single_api_xml_file)

# Additional test: os.walk yields empty list (directory exists but is empty)
@patch('xml.etree.ElementTree.parse')
@patch('os.walk')
@patch('os.path.isdir')
def test_empty_target_directories(mock_isdir, mock_os_walk, mock_et_parse, caplog):
    """Test when target directories exist but are empty."""
    mock_isdir.return_value = True # Directories exist
    dummy_package_path = "dummy_package"
    api_specs_full_path = os.path.join(dummy_package_path, API_SPECS_PATH_NAME)
    src_main_mule_full_path = os.path.join(dummy_package_path, SRC_MAIN_MULE_PATH_NAME)

    def os_walk_side_effect(path):
        if path == api_specs_full_path:
            return iter([]) # Empty directory for specs
        elif path == src_main_mule_full_path:
            return iter([]) # Empty directory for mule xmls
        return iter([])
    mock_os_walk.side_effect = os_walk_side_effect
    
    results = validate_api_spec_and_flows(dummy_package_path)

    assert results['api_spec_found'] is False
    assert results['api_definition_flow_found'] is False
    assert results['api_spec_files'] == []
    assert results['api_definition_flows'] == []
    
    assert any(
        f"No API specification files found in {api_specs_full_path}" in record.message
        for record in caplog.records if record.levelname == "WARNING"
    )
    assert any(
        f"No API definition flows found in XML files under {src_main_mule_full_path}" in record.message
        for record in caplog.records if record.levelname == "WARNING"
    )
    mock_et_parse.assert_not_called() # No XML files to parse
