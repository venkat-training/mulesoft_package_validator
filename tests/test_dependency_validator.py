import unittest
from unittest.mock import patch, MagicMock, mock_open
import os
import tempfile
import shutil
import xml.etree.ElementTree as ET
import subprocess
import sys

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

from mule_validator import dependency_validator

# Suppress logging for cleaner test output
logging.getLogger('mule_validator.dependency_validator').setLevel(logging.CRITICAL)

class TestFindSecretsInPomXml(unittest.TestCase):
    def _create_pom_root(self, pom_xml_string):
        return ET.fromstring(pom_xml_string)

    def test_pom_with_secret_property_tag_keyword(self):
        pom_content = """
<project xmlns="http://maven.apache.org/POM/4.0.0">
    <properties><db.password>secret_value_in_tag</db.password></properties>
</project>"""
        root = self._create_pom_root(pom_content)
        issues = dependency_validator.find_secrets_in_pom_xml(root, "pom.xml")
        self.assertTrue(any(i['issue_type'] == 'Hardcoded Secret' and i['xml_path'] == 'db.password' for i in issues))

    def test_pom_with_secret_property_value_pattern(self):
        # Example: A long Base64-like string in a property value
        pom_content = """
<project xmlns="http://maven.apache.org/POM/4.0.0">
    <properties><api.key>aBcDeFgHiJkLmNoPqRsTuVwXyZ0123456789+/=</api.key></properties>
</project>"""
        root = self._create_pom_root(pom_content)
        issues = dependency_validator.find_secrets_in_pom_xml(root, "pom.xml")
        self.assertTrue(any(i['issue_type'] == 'Suspicious Value' and i['xml_path'] == 'api.key' and "generic secret pattern" in i['message'] for i in issues))
        # Also, 'key' in 'api.key' tag might be caught as a keyword if it has text.
        self.assertTrue(any(i['issue_type'] == 'Hardcoded Secret' and i['xml_path'] == 'api.key' and "generic secret keyword" in i['message'] for i in issues))


    def test_pom_with_secret_attribute_keyword(self):
        pom_content = """
<project xmlns="http://maven.apache.org/POM/4.0.0">
    <build><plugins><plugin><configuration>
        <server id="myserver" username="admin" password="actual_password_value"/>
    </configuration></plugin></plugins></build>
</project>"""
        root = self._create_pom_root(pom_content)
        issues = dependency_validator.find_secrets_in_pom_xml(root, "pom.xml")
        self.assertTrue(any(i['issue_type'] == 'Hardcoded Secret' and i['attribute_name'] == 'password' for i in issues))

    def test_pom_with_secret_attribute_value_pattern(self):
        # Example: A JWT-like token in an attribute value
        jwt_like = "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.do_not_commit_this"
        pom_content = f"""
<project xmlns="http://maven.apache.org/POM/4.0.0">
    <properties><service.auth.token value="{jwt_like}"/></properties>
</project>""" # Using a properties element for simplicity of structure
        root = self._create_pom_root(pom_content)
        issues = dependency_validator.find_secrets_in_pom_xml(root, "pom.xml")
        # Check attribute value
        self.assertTrue(any(
            i['issue_type'] == 'Suspicious Value' and
            i['attribute_name'] == 'value' and
            i['xml_path'] == 'service.auth.token' and # Check correct element
            "generic secret pattern" in i['message']
            for i in issues
        ))
        # Check tag keyword
        self.assertTrue(any(
            i['issue_type'] == 'Hardcoded Secret' and
            i['xml_path'] == 'service.auth.token' and # Tag name
            not i['attribute_name'] and # Ensure it's about the tag, not an attribute of this tag
             "generic secret keyword" in i['message'] # 'token' in 'service.auth.token'
            for i in issues
        ))


    def test_pom_clean_no_secrets(self):
        pom_content = """
<project xmlns="http://maven.apache.org/POM/4.0.0">
    <properties><some.property>safe_value</some.property></properties>
</project>"""
        root = self._create_pom_root(pom_content)
        issues = dependency_validator.find_secrets_in_pom_xml(root, "pom.xml")
        self.assertEqual(len(issues), 0, f"Clean POM should have no issues. Got: {issues}")

    def test_find_secrets_in_pom_xml_root_is_none(self):
        issues = dependency_validator.find_secrets_in_pom_xml(None, "pom.xml")
        self.assertEqual(len(issues), 0)


class TestParsePomDependencies(unittest.TestCase):
    def setUp(self):
        self.test_dir = tempfile.mkdtemp()

    def tearDown(self):
        shutil.rmtree(self.test_dir)

    def _write_pom(self, content):
        p = os.path.join(self.test_dir, "pom.xml")
        with open(p, "w") as f:
            f.write(content)
        return p

    def test_parse_basic_dependencies(self):
        pom_content = """
<project xmlns="http://maven.apache.org/POM/4.0.0">
    <dependencies>
        <dependency><groupId>com.example</groupId><artifactId>artifact1</artifactId><version>1.0</version></dependency>
        <dependency><groupId>org.another</groupId><artifactId>artifact2</artifactId><version>2.1.3</version><type>pom</type></dependency>
        <dependency><groupId>com.third</groupId><artifactId>artifact3</artifactId><version>3.0</version><classifier>tests</classifier></dependency>
    </dependencies>
</project>"""
        pom_path = self._write_pom(pom_content)
        deps = dependency_validator.parse_pom_dependencies(pom_path)
        self.assertEqual(len(deps), 3)
        self.assertIn(("com.example", "artifact1", "1.0", None, "jar"), deps)
        self.assertIn(("org.another", "artifact2", "2.1.3", None, "pom"), deps)
        self.assertIn(("com.third", "artifact3", "3.0", "tests", "jar"), deps)

    def test_parse_no_dependencies_section(self):
        pom_content = "<project xmlns=\"http://maven.apache.org/POM/4.0.0\"></project>"
        pom_path = self._write_pom(pom_content)
        deps = dependency_validator.parse_pom_dependencies(pom_path)
        self.assertEqual(len(deps), 0)

    def test_parse_empty_dependencies_section(self):
        pom_content = "<project xmlns=\"http://maven.apache.org/POM/4.0.0\"><dependencies></dependencies></project>"
        pom_path = self._write_pom(pom_content)
        deps = dependency_validator.parse_pom_dependencies(pom_path)
        self.assertEqual(len(deps), 0)

    def test_parse_dependency_missing_version(self):
        # While not strictly valid for all cases, parser should handle it gracefully
        pom_content = """
<project xmlns="http://maven.apache.org/POM/4.0.0">
    <dependencies>
        <dependency><groupId>com.example</groupId><artifactId>artifact1</artifactId></dependency>
    </dependencies>
</project>"""
        pom_path = self._write_pom(pom_content)
        deps = dependency_validator.parse_pom_dependencies(pom_path)
        self.assertIn(("com.example", "artifact1", None, None, "jar"), deps)


    @patch('xml.etree.ElementTree.parse', side_effect=ET.ParseError("mocked parse error"))
    def test_parse_malformed_pom(self, mock_parse):
        # The actual content won't matter as parse is mocked to fail
        pom_path = self._write_pom("<project><unclosed></project>")
        deps = dependency_validator.parse_pom_dependencies(pom_path)
        self.assertEqual(len(deps), 0)
        # Optionally, check logger if your function logs this error
        # For now, just ensure it handles the error by returning an empty list.

    def test_parse_pom_file_not_found(self):
        deps = dependency_validator.parse_pom_dependencies(os.path.join(self.test_dir, "non_existent_pom.xml"))
        self.assertEqual(len(deps), 0)


class TestScanCodeForDependencies(unittest.TestCase):
    def setUp(self):
        self.test_dir = tempfile.mkdtemp()
    def tearDown(self):
        shutil.rmtree(self.test_dir)

    def _write_xml_file(self, name, content):
        p = os.path.join(self.test_dir, name)
        with open(p, "w") as f: f.write(content)
        return p

    def test_scan_finds_dependency_by_groupid(self):
        self._write_xml_file("flow.xml", "<mule><logger>com.example</logger></mule>")
        dependencies = [("com.example", "artifact1", "1.0", None, "jar")]
        used = dependency_validator.scan_code_for_dependencies(self.test_dir, dependencies)
        self.assertEqual(used, {dependencies[0]})

    def test_scan_finds_dependency_by_artifactid(self):
        self._write_xml_file("flow.xml", "<mule><http:request config-ref=\"artifact1_config\"/></mule>")
        dependencies = [("com.example", "artifact1", "1.0", None, "jar")]
        used = dependency_validator.scan_code_for_dependencies(self.test_dir, dependencies)
        self.assertEqual(used, {dependencies[0]})

    def test_scan_no_match(self):
        self._write_xml_file("flow.xml", "<mule><logger>unrelated.text</logger></mule>")
        dependencies = [("com.example", "artifact1", "1.0", None, "jar")]
        used = dependency_validator.scan_code_for_dependencies(self.test_dir, dependencies)
        self.assertEqual(len(used), 0)

    def test_scan_empty_dependencies_list(self):
        self._write_xml_file("flow.xml", "<mule />")
        used = dependency_validator.scan_code_for_dependencies(self.test_dir, [])
        self.assertEqual(len(used), 0)

    def test_scan_no_xml_files(self):
        # Create a non-XML file
        with open(os.path.join(self.test_dir, "config.properties"), "w") as f: f.write("key=value")
        dependencies = [("com.example", "artifact1", "1.0", None, "jar")]
        used = dependency_validator.scan_code_for_dependencies(self.test_dir, dependencies)
        self.assertEqual(len(used), 0)

    @patch('builtins.open', side_effect=IOError("mocked read error"))
    def test_scan_file_read_error(self, mock_open_error):
        # Need to make os.walk find a file first
        with patch('os.walk', return_value=[(self.test_dir, [], ['error_file.xml'])]):
            dependencies = [("com.example", "artifact1", "1.0", None, "jar")]
            used = dependency_validator.scan_code_for_dependencies(self.test_dir, dependencies)
            self.assertEqual(len(used), 0) # Should gracefully handle error


class TestCalculateBuildSize(unittest.TestCase):
    def setUp(self):
        self.test_dir = tempfile.mkdtemp()
    def tearDown(self):
        shutil.rmtree(self.test_dir)

    @patch('os.path.getsize')
    @patch('os.walk')
    def test_calculate_size(self, mock_walk, mock_getsize):
        mock_walk.return_value = [
            (self.test_dir, [], ["file1.jar", "file2.xml"]),
            (os.path.join(self.test_dir, "lib"), [], ["lib1.jar"]),
        ]
        def getsize_side_effect(path):
            if path.endswith("file1.jar"): return 1000
            if path.endswith("file2.xml"): return 500
            if path.endswith("lib1.jar"): return 2000
            return 0
        mock_getsize.side_effect = getsize_side_effect
        
        size = dependency_validator.calculate_build_size(self.test_dir)
        self.assertEqual(size, 3500)

    @patch('os.walk', return_value=[]) # Empty directory
    def test_calculate_size_empty_dir(self, mock_walk_empty):
        size = dependency_validator.calculate_build_size(self.test_dir)
        self.assertEqual(size, 0)

    @patch('os.path.isdir', return_value=False) # Directory does not exist
    def test_calculate_size_non_existent_dir(self, mock_isdir_false):
        size = dependency_validator.calculate_build_size("/path/does/not/exist")
        self.assertEqual(size, 0)
        # Optionally check logger warning if implemented


class TestCheckDependencyJars(unittest.TestCase):
    def setUp(self):
        self.target_dir = tempfile.mkdtemp(prefix="target_")
        self.m2_repo_patcher = patch('os.path.expanduser', return_value=os.path.join(tempfile.gettempdir(), ".m2_test_repo"))
        self.mock_m2_repo_path = self.m2_repo_patcher.start()
        os.makedirs(os.path.join(self.mock_m2_repo_path, "repository", "com", "example", "artifact1", "1.0"), exist_ok=True)
        # Create a dummy artifact in the mock .m2 repo
        with open(os.path.join(self.mock_m2_repo_path, "repository", "com", "example", "artifact1", "1.0", "artifact1-1.0.jar"), "w") as f:
            f.write("dummy jar content")

    def tearDown(self):
        shutil.rmtree(self.target_dir)
        self.m2_repo_patcher.stop()
        if os.path.exists(self.mock_m2_repo_path): # Clean up mock .m2
            shutil.rmtree(self.mock_m2_repo_path)

    def test_jar_found_in_target(self):
        # Create dummy jar in target
        with open(os.path.join(self.target_dir, "artifact2-2.0.jar"), "w") as f: f.write("content")
        dependencies = [("com.another", "artifact2", "2.0", None, "jar")]
        missing = dependency_validator.check_dependency_jars(self.target_dir, dependencies)
        self.assertEqual(len(missing), 0)

    def test_jar_found_in_m2_repo(self):
        dependencies = [("com.example", "artifact1", "1.0", None, "jar")]
        missing = dependency_validator.check_dependency_jars(self.target_dir, dependencies)
        self.assertEqual(len(missing), 0)

    def test_jar_missing_everywhere(self):
        dependencies = [("com.missing", "artifact3", "3.0", None, "jar")]
        missing = dependency_validator.check_dependency_jars(self.target_dir, dependencies)
        self.assertEqual(missing, ["artifact3-3.0.jar"])

    def test_jar_with_classifier_and_type(self):
        # Create dummy zip in target
        with open(os.path.join(self.target_dir, "artifact4-4.0-classifier.zip"), "w") as f: f.write("content")
        dependencies = [("com.foo", "artifact4", "4.0", "classifier", "zip")]
        missing = dependency_validator.check_dependency_jars(self.target_dir, dependencies)
        self.assertEqual(len(missing), 0)

    def test_dependency_no_version_skipped(self):
        dependencies = [("com.skipped", "artifact-no-version", None, None, "jar")]
        missing = dependency_validator.check_dependency_jars(self.target_dir, dependencies)
        self.assertEqual(len(missing), 0)


class TestCheckDependencyResolution(unittest.TestCase):
    # Note: Hardcoded mvn path in module makes this harder to test reliably across environments.
    # We will mock subprocess.run.

    @patch('os.path.isfile', return_value=True) # Assume found in local .m2
    def test_resolution_found_locally(self, mock_isfile):
        self.assertTrue(dependency_validator.check_dependency_resolution("com.example", "lib1", "1.0"))
        mock_isfile.assert_called_once() # Verifies it checked .m2

    @patch('os.path.isfile', return_value=False) # Not in local .m2
    @patch('subprocess.run')
    def test_resolution_via_maven_success(self, mock_subprocess_run, mock_isfile):
        mock_subprocess_run.return_value = MagicMock(returncode=0)
        self.assertTrue(dependency_validator.check_dependency_resolution("com.example", "lib2", "2.0", dep_type="pom"))
        mock_subprocess_run.assert_called_once()
        # Verify command construction (simplified check)
        args, kwargs = mock_subprocess_run.call_args
        self.assertIn("dependency:get", args[0])
        self.assertIn("-Dartifact=com.example:lib2:2.0@pom", args[0])

    @patch('os.path.isfile', return_value=False)
    @patch('subprocess.run')
    def test_resolution_via_maven_failure(self, mock_subprocess_run, mock_isfile):
        mock_subprocess_run.return_value = MagicMock(returncode=1)
        self.assertFalse(dependency_validator.check_dependency_resolution("com.example", "lib-fail", "1.0"))

    @patch('os.path.isfile', return_value=False)
    @patch('subprocess.run', side_effect=subprocess.TimeoutExpired(cmd="mvn", timeout=1))
    def test_resolution_via_maven_timeout(self, mock_subprocess_run_timeout, mock_isfile):
        self.assertFalse(dependency_validator.check_dependency_resolution("com.example", "lib-timeout", "1.0"))

    def test_resolution_no_version(self):
        self.assertFalse(dependency_validator.check_dependency_resolution("com.example", "lib-no-ver", None))


class TestFindDuplicateDependencies(unittest.TestCase):
    def test_no_duplicates(self):
        deps = [("g1","a1","1.0",None,"jar"), ("g1","a2","1.0",None,"jar")]
        self.assertEqual(len(dependency_validator.find_duplicate_dependencies(deps)), 0)

    def test_simple_duplicate_gact(self): # GroupId, ArtifactId, Classifier, Type
        deps = [("g1","a1","1.0",None,"jar"), ("g1","a1","2.0",None,"jar")]
        self.assertEqual(dependency_validator.find_duplicate_dependencies(deps), ["g1:a1"])

    def test_duplicate_with_classifier_and_type(self):
        deps = [
            ("g1","a1","1.0","tests","test-jar"),
            ("g1","a1","2.0","tests","test-jar")
        ]
        self.assertEqual(dependency_validator.find_duplicate_dependencies(deps), ["g1:a1:tests:test-jar"])

    def test_multiple_duplicates(self):
        deps = [
            ("g1","a1","1.0",None,"jar"), ("g1","a1","2.0",None,"jar"), # dup1
            ("g2","a2","1.0","c1","zip"), ("g2","a2","2.0","c1","zip"), # dup2
            ("g3","a3","1.0",None,"jar")
        ]
        duplicates = dependency_validator.find_duplicate_dependencies(deps)
        self.assertEqual(len(duplicates), 2)
        self.assertIn("g1:a1", duplicates)
        self.assertIn("g2:a2:c1:zip", duplicates)


class TestValidatePomDependencies(unittest.TestCase):
    @patch('mule_validator.dependency_validator.parse_pom_dependencies')
    @patch('mule_validator.dependency_validator.check_dependency_jars')
    @patch('mule_validator.dependency_validator.check_dependency_resolution')
    @patch('mule_validator.dependency_validator.find_duplicate_dependencies')
    def test_validate_pom_dependencies_orchestration(self, mock_find_dup, mock_check_res, mock_check_jars, mock_parse_deps):
        mock_deps_list = [("g","a","v",None,"jar")]
        mock_parse_deps.return_value = mock_deps_list
        mock_check_jars.return_value = ["missing.jar"]
        # Let check_dependency_resolution return True for the one dependency
        mock_check_res.return_value = True
        mock_find_dup.return_value = ["g:a"] # Example duplicate

        results = dependency_validator.validate_pom_dependencies("dummy_pom.xml", "dummy_target")

        mock_parse_deps.assert_called_once_with("dummy_pom.xml")
        mock_check_jars.assert_called_once_with("dummy_target", mock_deps_list)
        mock_check_res.assert_called_once_with("g","a","v",None,"jar")
        mock_find_dup.assert_called_once_with(mock_deps_list)

        self.assertEqual(results["all_dependencies"], mock_deps_list)
        self.assertEqual(results["missing_jars"], ["missing.jar"])
        self.assertEqual(results["unresolved_dependencies"], []) # Since check_res returned True
        self.assertEqual(results["duplicate_dependencies"], ["g:a"])

    @patch('mule_validator.dependency_validator.parse_pom_dependencies')
    @patch('mule_validator.dependency_validator.check_dependency_jars')
    @patch('mule_validator.dependency_validator.check_dependency_resolution', return_value=False) # Simulate unresolved
    @patch('mule_validator.dependency_validator.find_duplicate_dependencies')
    def test_validate_pom_dependencies_unresolved(self, mock_find_dup, mock_check_res_false, mock_check_jars, mock_parse_deps):
        mock_deps_list = [("g","unresolved","1.0",None,"jar")]
        mock_parse_deps.return_value = mock_deps_list
        mock_check_jars.return_value = []
        mock_find_dup.return_value = []

        results = dependency_validator.validate_pom_dependencies("dummy_pom.xml", "dummy_target")
        self.assertEqual(results["unresolved_dependencies"], ["g:unresolved:1.0"])


class TestValidateAllProjects(unittest.TestCase):
    def setUp(self):
        self.test_dir = tempfile.mkdtemp()
    def tearDown(self):
        shutil.rmtree(self.test_dir)

    @patch('os.path.isfile', return_value=True)
    @patch('mule_validator.dependency_validator.validate_pom_dependencies')
    def test_validate_all_projects_pom_exists(self, mock_validate_pom, mock_isfile):
        mock_pom_results = {"all_dependencies": [("g","a","v",None,"jar")]}
        mock_validate_pom.return_value = mock_pom_results
        
        pom_path = os.path.join(self.test_dir, "pom.xml")
        report = dependency_validator.validate_all_projects(self.test_dir)

        mock_isfile.assert_called_once_with(pom_path)
        mock_validate_pom.assert_called_once_with(pom_path, os.path.join(self.test_dir, "target"))
        self.assertIn(pom_path, report)
        self.assertEqual(report[pom_path], mock_pom_results)

    @patch('os.path.isfile', return_value=False)
    @patch('mule_validator.dependency_validator.validate_pom_dependencies')
    @patch('mule_validator.dependency_validator.logger')
    def test_validate_all_projects_pom_missing(self, mock_logger, mock_validate_pom, mock_isfile):
        report = dependency_validator.validate_all_projects(self.test_dir)

        pom_path = os.path.join(self.test_dir, "pom.xml")
        mock_isfile.assert_called_once_with(pom_path)
        mock_validate_pom.assert_not_called()
        self.assertEqual(len(report), 0)
        mock_logger.warning.assert_called_with(f"No pom.xml found in {self.test_dir}")


if __name__ == '__main__':
    unittest.main(verbosity=2)
