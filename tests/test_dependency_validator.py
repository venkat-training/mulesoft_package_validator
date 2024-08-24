import unittest
from mule_validator.dependency_validator import parse_pom_dependencies, scan_code_for_dependencies, calculate_build_size

class TestDependencyValidator(unittest.TestCase):

    def test_parse_pom_dependencies(self):
        # Test with a sample pom.xml content
        pom_file_path = 'tests/test_data/sample_pom.xml'
        dependencies = parse_pom_dependencies(pom_file_path)
        expected_dependencies = ['org.example:example-dependency', 'org.example:another-dependency']
        self.assertEqual(dependencies, expected_dependencies)

    def test_scan_code_for_dependencies(self):
        # Test with a sample MuleSoft package
        package_folder_path = 'tests/test_data/sample_package'
        dependencies = ['org.example:example-dependency']
        used_dependencies = scan_code_for_dependencies(package_folder_path, dependencies)
        self.assertIn('org.example:example-dependency', used_dependencies)

    def test_calculate_build_size(self):
        # Test with a sample build folder
        build_folder_path = 'tests/test_data/sample_build'
        build_size = calculate_build_size(build_folder_path)
        self.assertGreater(build_size, 0)

if __name__ == '__main__':
    unittest.main()
