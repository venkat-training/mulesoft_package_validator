import pytest
import os
import xml.etree.ElementTree as ET
from unittest.mock import patch, MagicMock, mock_open

from mule_validator.dependency_validator import (
    parse_pom_dependencies,
    scan_code_for_dependencies,
    calculate_build_size,
    validate_dependencies_and_size,
    MAVEN_POM_NAMESPACE  # Import if used directly in tests, or assume it's used internally
)

# Mock the logger for all tests in this module
@pytest.fixture(autouse=True)
def mock_logger():
    with patch('mule_validator.dependency_validator.logger', MagicMock()) as mock_log:
        yield mock_log

# 1. Tests for parse_pom_dependencies
@patch('xml.etree.ElementTree.parse')
def test_parse_pom_dependencies_valid(mock_et_parse):
    """Test parsing a valid POM file with dependencies."""
    mock_dependency_element1 = MagicMock()
    mock_dependency_element1.find(f"{{{MAVEN_POM_NAMESPACE}}}groupId").text = "group1"
    mock_dependency_element1.find(f"{{{MAVEN_POM_NAMESPACE}}}artifactId").text = "artifact1"

    mock_dependency_element2 = MagicMock()
    mock_dependency_element2.find(f"{{{MAVEN_POM_NAMESPACE}}}groupId").text = "group2"
    mock_dependency_element2.find(f"{{{MAVEN_POM_NAMESPACE}}}artifactId").text = "artifact2"

    mock_root = MagicMock()
    mock_root.findall(f".//{{{MAVEN_POM_NAMESPACE}}}dependency").return_value = [
        mock_dependency_element1, mock_dependency_element2
    ]
    mock_tree = MagicMock()
    mock_tree.getroot.return_value = mock_root
    mock_et_parse.return_value = mock_tree

    dependencies = parse_pom_dependencies("dummy_pom.xml")
    assert dependencies == ["group1:artifact1", "group2:artifact2"]
    mock_et_parse.assert_called_once_with("dummy_pom.xml")

@patch('xml.etree.ElementTree.parse')
def test_parse_pom_dependencies_no_dependencies(mock_et_parse):
    """Test parsing a POM file with no dependencies."""
    mock_root = MagicMock()
    mock_root.findall(f".//{{{MAVEN_POM_NAMESPACE}}}dependency").return_value = []
    mock_tree = MagicMock()
    mock_tree.getroot.return_value = mock_root
    mock_et_parse.return_value = mock_tree

    dependencies = parse_pom_dependencies("dummy_pom.xml")
    assert dependencies == []

@patch('xml.etree.ElementTree.parse')
def test_parse_pom_dependencies_parse_error(mock_et_parse, caplog):
    """Test parsing a POM file that causes an ET.ParseError."""
    mock_et_parse.side_effect = ET.ParseError("mocked parse error")
    
    dependencies = parse_pom_dependencies("dummy_pom.xml")
    assert dependencies == []
    
    assert any(
        "Error parsing POM file: dummy_pom.xml - mocked parse error" in record.message 
        for record in caplog.records if record.levelname == "ERROR"
    )

@patch('xml.etree.ElementTree.parse')
def test_parse_pom_dependencies_missing_group_or_artifact(mock_et_parse, caplog):
    """Test POM with dependencies missing groupId or artifactId."""
    mock_dep1_valid = MagicMock()
    mock_dep1_valid.find(f"{{{MAVEN_POM_NAMESPACE}}}groupId").text = "group1"
    mock_dep1_valid.find(f"{{{MAVEN_POM_NAMESPACE}}}artifactId").text = "artifact1"

    mock_dep2_missing_group = MagicMock()
    # Make find for groupId return None, or have .text be None
    mock_group_id_element_none = MagicMock()
    mock_group_id_element_none.text = None
    mock_dep2_missing_group.find(f"{{{MAVEN_POM_NAMESPACE}}}groupId").return_value = None # Simulate element not found
    mock_dep2_missing_group.find(f"{{{MAVEN_POM_NAMESPACE}}}artifactId").text = "artifact2"


    mock_dep3_missing_artifact_text = MagicMock()
    mock_dep3_missing_artifact_text.find(f"{{{MAVEN_POM_NAMESPACE}}}groupId").text = "group3"
    mock_artifact_id_element_none = MagicMock()
    mock_artifact_id_element_none.text = None # Simulate element found but no text
    mock_dep3_missing_artifact_text.find(f"{{{MAVEN_POM_NAMESPACE}}}artifactId").return_value = mock_artifact_id_element_none


    mock_root = MagicMock()
    mock_root.findall(f".//{{{MAVEN_POM_NAMESPACE}}}dependency").return_value = [
        mock_dep1_valid, mock_dep2_missing_group, mock_dep3_missing_artifact_text
    ]
    mock_tree = MagicMock()
    mock_tree.getroot.return_value = mock_root
    mock_et_parse.return_value = mock_tree

    dependencies = parse_pom_dependencies("dummy_pom.xml")
    assert dependencies == ["group1:artifact1"] # Only the valid one
    
    # Check for warnings (assuming the main code logs a warning)
    # The refactored code should log warnings for malformed entries
    assert any(
        "Found a dependency without groupId or artifactId in dummy_pom.xml" in record.message
        for record in caplog.records if record.levelname == "WARNING"
    )


# 2. Tests for scan_code_for_dependencies
@patch('os.walk')
@patch('builtins.open', new_callable=mock_open)
def test_scan_code_for_dependencies_used(mock_file_open, mock_os_walk):
    """Test scanning code where dependencies are used."""
    mock_os_walk.return_value = [
        ('/path', [], ['file1.xml'])
    ]
    mock_file_open.return_value.read.return_value = "<config>group1:artifact1</config>"
    
    dependencies = ["group1:artifact1", "group2:artifact2"]
    used = scan_code_for_dependencies("/path", dependencies)
    assert used == {"group1:artifact1"}
    mock_file_open.assert_called_once_with(os.path.join('/path', 'file1.xml'), 'r', encoding='utf-8')

@patch('os.walk')
@patch('builtins.open', new_callable=mock_open)
def test_scan_code_for_dependencies_none_used(mock_file_open, mock_os_walk):
    """Test scanning code where no listed dependencies are used."""
    mock_os_walk.return_value = [
        ('/path', [], ['file1.xml'])
    ]
    mock_file_open.return_value.read.return_value = "<config>other:stuff</config>"
    
    dependencies = ["group1:artifact1", "group2:artifact2"]
    used = scan_code_for_dependencies("/path", dependencies)
    assert used == set()

@patch('os.walk')
@patch('builtins.open', new_callable=mock_open)
def test_scan_code_for_dependencies_read_error(mock_file_open, mock_os_walk, caplog):
    """Test scanning code when a file read error occurs."""
    mock_os_walk.return_value = [
        ('/path', [], ['file1.xml'])
    ]
    mock_file_open.return_value.read.side_effect = IOError("mocked read error")
    
    dependencies = ["group1:artifact1"]
    used = scan_code_for_dependencies("/path", dependencies)
    assert used == set() # Should be empty as the file read failed
    
    expected_log_message = f"Error reading or processing file: {os.path.join('/path', 'file1.xml')} - mocked read error"
    assert any(
        expected_log_message in record.message for record in caplog.records if record.levelname == "ERROR"
    )

@patch('os.walk')
def test_scan_code_for_dependencies_empty_list(mock_os_walk):
    """Test scanning with an empty list of dependencies to find."""
    used = scan_code_for_dependencies("/path", [])
    assert used == set()
    mock_os_walk.assert_not_called() # Optimization: if no deps, don't walk

# 3. Tests for calculate_build_size
@patch('os.walk')
@patch('os.path.getsize')
def test_calculate_build_size_multiple_files(mock_getsize, mock_os_walk):
    """Test calculating build size with multiple files and directories."""
    mock_os_walk.return_value = [
        ('/path', ['subdir'], ['file1.jar']),
        ('/path/subdir', [], ['file2.xml', 'file3.dat'])
    ]
    
    def getsize_side_effect(path):
        if path == os.path.join('/path', 'file1.jar'): return 1000
        if path == os.path.join('/path/subdir', 'file2.xml'): return 500
        if path == os.path.join('/path/subdir', 'file3.dat'): return 200
        return 0
    mock_getsize.side_effect = getsize_side_effect
    
    total_size = calculate_build_size("/path")
    assert total_size == 1700

@patch('os.walk')
def test_calculate_build_size_empty_directory(mock_os_walk):
    """Test calculating build size for an empty directory."""
    mock_os_walk.return_value = [
        ('/path', [], [])
    ]
    total_size = calculate_build_size("/path")
    assert total_size == 0

@patch('os.walk')
@patch('os.path.getsize')
def test_calculate_build_size_getsize_error(mock_getsize, mock_os_walk, caplog):
    """Test build size calculation when os.path.getsize raises an OSError for a file."""
    mock_os_walk.return_value = [
        ('/path', [], ['file1.jar', 'error_file.dat', 'file2.xml'])
    ]
    
    def getsize_side_effect(path):
        if path == os.path.join('/path', 'file1.jar'): return 1000
        if path == os.path.join('/path', 'error_file.dat'): raise OSError("Permission denied")
        if path == os.path.join('/path', 'file2.xml'): return 500
        return 0
    mock_getsize.side_effect = getsize_side_effect
    
    # The current implementation of calculate_build_size does not catch this error.
    # So, we expect the OSError to propagate.
    with pytest.raises(OSError, match="Permission denied"):
         calculate_build_size("/path")

    # If the implementation were changed to catch and log:
    # total_size = calculate_build_size("/path")
    # assert total_size == 1500 # Sum of non-error files
    # assert "Could not get size for /path/error_file.dat: Permission denied" in caplog.text


# 4. Tests for validate_dependencies_and_size
@patch('mule_validator.dependency_validator.parse_pom_dependencies')
@patch('mule_validator.dependency_validator.scan_code_for_dependencies')
@patch('mule_validator.dependency_validator.calculate_build_size')
@patch('os.path.isfile')
def test_validate_dependencies_successful(
    mock_isfile, mock_calc_size, mock_scan_code, mock_parse_pom
):
    """Test successful validation scenario."""
    mock_isfile.return_value = True # pom.xml exists
    mock_parse_pom.return_value = ["dep1:foo", "dep2:bar", "dep3:baz"]
    mock_scan_code.return_value = {"dep1:foo", "dep2:bar"}
    mock_calc_size.return_value = 50 * 1024 * 1024 # 50MB
    
    result = validate_dependencies_and_size("/path", "/buildpath", max_size_mb=100)
    
    assert sorted(result['unused_dependencies']) == sorted(["dep3:baz"]) # Convert set to list for comparison
    assert result['build_size_mb'] == 50.0
    assert result['size_ok'] is True
    assert result['max_size_mb'] == 100
    mock_isfile.assert_called_once_with(os.path.join("/path", 'pom.xml'))

@patch('mule_validator.dependency_validator.parse_pom_dependencies')
@patch('mule_validator.dependency_validator.scan_code_for_dependencies')
@patch('mule_validator.dependency_validator.calculate_build_size')
@patch('os.path.isfile')
def test_validate_dependencies_build_size_exceeded(
    mock_isfile, mock_calc_size, mock_scan_code, mock_parse_pom, caplog
):
    """Test validation when build size is exceeded."""
    mock_isfile.return_value = True
    mock_parse_pom.return_value = ["dep1:foo"]
    mock_scan_code.return_value = {"dep1:foo"}
    mock_calc_size.return_value = 150 * 1024 * 1024 # 150MB
    
    result = validate_dependencies_and_size("/path", "/buildpath", max_size_mb=100)
    
    assert result['size_ok'] is False
    assert result['build_size_mb'] == 150.0
    assert any(
        "Build size 150.00MB exceeds maximum of 100MB" in record.message 
        for record in caplog.records if record.levelname == "WARNING"
    )

@patch('os.path.isfile')
def test_validate_dependencies_pom_not_found(mock_isfile, caplog):
    """Test validation when pom.xml is not found."""
    mock_isfile.return_value = False # pom.xml does not exist
    
    with pytest.raises(FileNotFoundError, match="POM file not found at path: /path/pom.xml"):
        validate_dependencies_and_size("/path", "/buildpath")
    
    assert any(
        "POM file not found at path: /path/pom.xml" in record.message
        for record in caplog.records if record.levelname == "ERROR"
    )

@patch('mule_validator.dependency_validator.parse_pom_dependencies')
@patch('mule_validator.dependency_validator.scan_code_for_dependencies')
@patch('mule_validator.dependency_validator.calculate_build_size')
@patch('os.path.isfile')
def test_validate_dependencies_pom_parsing_failure(
    mock_isfile, mock_calc_size, mock_scan_code, mock_parse_pom, caplog
):
    """Test validation when POM parsing fails (returns empty list and logs error)."""
    mock_isfile.return_value = True
    # parse_pom_dependencies itself would log an error, we simulate its outcome:
    mock_parse_pom.return_value = [] 
    mock_scan_code.return_value = set() # No dependencies to scan for
    mock_calc_size.return_value = 10 * 1024 * 1024 # 10MB
    
    result = validate_dependencies_and_size("/path", "/buildpath")
    
    assert result['unused_dependencies'] == []
    assert result['size_ok'] is True
    
    # Check for the warning from validate_dependencies_and_size
    assert any(
        "No dependencies found or POM parsing failed for /path/pom.xml. Proceeding with empty dependency list." in record.message
        for record in caplog.records if record.levelname == "WARNING"
    )

@patch('mule_validator.dependency_validator.parse_pom_dependencies')
@patch('mule_validator.dependency_validator.scan_code_for_dependencies')
@patch('mule_validator.dependency_validator.calculate_build_size')
@patch('os.path.isfile')
def test_validate_dependencies_calculate_build_size_os_error(
    mock_isfile, mock_calc_size, mock_scan_code, mock_parse_pom, caplog
):
    """Test validation when calculate_build_size encounters an OSError."""
    mock_isfile.return_value = True
    mock_parse_pom.return_value = ["dep1:foo"]
    mock_scan_code.return_value = {"dep1:foo"}
    mock_calc_size.side_effect = OSError("Disk read error")

    result = validate_dependencies_and_size("/path", "/buildpath", max_size_mb=100)

    assert result['build_size_mb'] == 0.0 # Should default to 0 or handle error appropriately
    assert result['size_ok'] is True # 0 MB is <= 100 MB
    assert any(
        "Could not calculate build size for /buildpath: Disk read error" in record.message
        for record in caplog.records if record.levelname == "ERROR"
    )
    # The size_ok might be True because build_size_mb becomes 0 after error.
    # Depending on desired behavior, this might need adjustment or a specific error state.
    # Current refactored code logs error and build_size_mb is 0, so size_ok is True.
