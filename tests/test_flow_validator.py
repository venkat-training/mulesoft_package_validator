import unittest
from mule_validator.flow_validator import count_flows_and_components, validate_flows_in_package

class TestFlowValidator(unittest.TestCase):

    def test_count_flows_and_components(self):
        # Test with a sample XML file
        xml_file_path = 'tests/test_data/sample_flow.xml'
        counts = count_flows_and_components(xml_file_path)
        expected_counts = {'flows': 1, 'sub_flows': 0, 'components': 2}
        self.assertEqual(counts, expected_counts)

    def test_validate_flows_in_package(self):
        # Test with a sample MuleSoft package
        package_folder_path = 'tests/test_data/sample_package'
        results = validate_flows_in_package(package_folder_path)
        self.assertTrue(results['flow_status'])
        self.assertTrue(results['sub_flow_status'])
        self.assertTrue(results['component_status'])

if __name__ == '__main__':
    unittest.main()
