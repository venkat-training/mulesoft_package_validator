import unittest
from mule_validator.api_validator import validate_api_spec_and_flows

class TestApiValidator(unittest.TestCase):

    def test_validate_api_spec_and_flows(self):
        # Test with a sample MuleSoft package
        package_folder_path = 'tests/test_data/sample_package'
        results = validate_api_spec_and_flows(package_folder_path)
        self.assertTrue(results['spec_status'])
        self.assertTrue(results['definition_flow_status'])

if __name__ == '__main__':
    unittest.main()
