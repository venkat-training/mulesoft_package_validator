import pytest
import logging
from unittest.mock import patch
import xml.etree.ElementTree as ET
from mule_validator.flow_validator import count_flows_and_components

@patch('mule_validator.flow_validator.ET.parse')
def test_count_flows_and_components_parse_error(mock_et_parse, caplog):
    """
    Test that count_flows_and_components handles ET.ParseError correctly.
    - It should return zero counts.
    - It should log an ERROR with the parse error message.
    """

    # Arrange: force ET.parse to raise a ParseError
    mock_et_parse.side_effect = ET.ParseError("mocked xml parse error")

    # Make sure caplog captures logs from the flow_validator logger
    caplog.set_level(logging.ERROR, logger='mule_validator.flow_validator')

    # Act
    counts, invalid_names = count_flows_and_components("dummy.xml")

    # Assert counts
    assert counts == {'flows': 0, 'sub_flows': 0, 'components': 0}, "Counts should be zero on parse error"
    assert invalid_names == [], "Invalid names should be empty on parse error"

    # Assert that an ERROR log was emitted with the correct message
    expected_message = "Error parsing XML file: dummy.xml - mocked xml parse error"
    # Use any() to check if message appears in any log record
    assert any(expected_message in record.message for record in caplog.records), \
        f"Expected log message not found. Captured logs: {[r.message for r in caplog.records]}"
