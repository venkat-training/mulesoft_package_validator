import unittest
import os
import tempfile
import shutil
import yaml
from unittest.mock import patch, mock_open, MagicMock
import sys

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

from mule_validator import configfile_validator

# Suppress logging for cleaner test output
logging.getLogger('mule_validator.configfile_validator').setLevel(logging.CRITICAL)

class TestValidateYamlFileSyntax(unittest.TestCase):
    def setUp(self):
        self.test_dir = tempfile.mkdtemp()

    def tearDown(self):
        shutil.rmtree(self.test_dir)

    def _write_temp_yaml(self, filename, content_str):
        file_path = os.path.join(self.test_dir, filename)
        with open(file_path, 'w', encoding='utf-8') as f:
            f.write(content_str)
        return file_path

    def test_valid_yaml_syntax(self):
        file_path = self._write_temp_yaml("valid.yaml", "key: value\nlist:\n  - item1\n  - item2")
        is_valid, error_message = configfile_validator.validate_yaml_file(file_path)
        self.assertTrue(is_valid)
        self.assertIsNone(error_message)

    def test_invalid_yaml_syntax_indentation(self):
        file_path = self._write_temp_yaml("invalid_indent.yaml", "key: value\n list:\n- item1") # Bad indent for list
        is_valid, error_message = configfile_validator.validate_yaml_file(file_path)
        self.assertFalse(is_valid)
        self.assertIsNotNone(error_message)
        self.assertIn("mapping values are not allowed here", error_message) # Example error text

    def test_invalid_yaml_syntax_unclosed_quote(self):
        file_path = self._write_temp_yaml("invalid_quote.yaml", "key: 'unclosed value")
        is_valid, error_message = configfile_validator.validate_yaml_file(file_path)
        self.assertFalse(is_valid)
        self.assertIsNotNone(error_message)
        self.assertIn("scan_to_next_token", error_message) # Error from scanner

    def test_empty_yaml_file_syntax(self):
        # An empty file is valid YAML (represents None)
        file_path = self._write_temp_yaml("empty.yaml", "")
        is_valid, error_message = configfile_validator.validate_yaml_file(file_path)
        self.assertTrue(is_valid)
        self.assertIsNone(error_message)

    def test_yaml_with_only_comments_syntax(self):
        # A file with only comments is valid YAML (represents None)
        file_path = self._write_temp_yaml("comments_only.yaml", "# Comment line 1\n# Comment line 2")
        is_valid, error_message = configfile_validator.validate_yaml_file(file_path)
        self.assertTrue(is_valid)
        self.assertIsNone(error_message)

    def test_validate_yaml_file_not_found(self):
        # validate_yaml_file itself doesn't check existence, relies on open()
        with self.assertRaises(FileNotFoundError):
            configfile_validator.validate_yaml_file(os.path.join(self.test_dir, "non_existent.yaml"))


class TestCheckYamlContentRules(unittest.TestCase): # Renamed from TestConfigFileValidatorSecurity
    def setUp(self):
        self.test_dir = tempfile.mkdtemp()

    def tearDown(self):
        shutil.rmtree(self.test_dir)

    def _write_temp_yaml_file(self, filename, content_dict=None, content_str=None):
        file_path = os.path.join(self.test_dir, filename)
        with open(file_path, 'w', encoding='utf-8') as f:
            if content_dict is not None:
                yaml.dump(content_dict, f, sort_keys=False)
            elif content_str is not None:
                f.write(content_str)
            else:
                raise ValueError("Either content_dict or content_str must be provided")
        return file_path

    def test_yaml_with_keyword_secret(self):
        yaml_content = {
            "user": {"name": "testuser", "password": "actual_password123"}, # Keyword "password"
            "api_access": {"key": "somekey", "secretkey": "thisIsASecretKey123!"} # Keyword "secretkey"
        }
        file_path = self._write_temp_yaml_file("keyword_secret.yaml", content_dict=yaml_content)
        
        # Test with secure properties enabled (should warn about plaintext)
        issues_sp_true = configfile_validator.check_yaml_content_rules(file_path, project_uses_secure_properties=True)
        self.assertTrue(any("Key 'user.password' (contains sensitive keyword 'password') has a plaintext value" in issue for issue in issues_sp_true))
        self.assertTrue(any("Key 'api_access.secretkey' (contains sensitive keyword 'secretkey') has a plaintext value" in issue for issue in issues_sp_true))

        # Test with secure properties disabled (should warn about potential plaintext)
        issues_sp_false = configfile_validator.check_yaml_content_rules(file_path, project_uses_secure_properties=False)
        self.assertTrue(any("Key 'user.password' (contains sensitive keyword 'password') may contain plaintext sensitive data" in issue for issue in issues_sp_false))
        self.assertTrue(any("Key 'api_access.secretkey' (contains sensitive keyword 'secretkey') may contain plaintext sensitive data" in issue for issue in issues_sp_false))


    def test_yaml_with_value_pattern_secret_jwt(self):
        jwt_token = "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c"
        yaml_content_str = f"settings:\n  token: {jwt_token}\n  another_setting: some_value"
        file_path = self._write_temp_yaml_file("value_pattern_secret.yaml", content_str=yaml_content_str)
        
        issues = configfile_validator.check_yaml_content_rules(file_path, project_uses_secure_properties=True)
        self.assertTrue(any("Value for key 'settings.token' appears to be a generic secret/API key" in issue for issue in issues))

    def test_yaml_with_generic_base64_pattern(self):
        base64_val = "aBcDeFgHiJkLmNoPqRsTuVwXyZ0123456789+/=" # 39 chars
        yaml_content_str = f"credentials:\n  encoded: {base64_val}"
        file_path = self._write_temp_yaml_file("generic_base64.yaml", content_str=yaml_content_str)
        issues = configfile_validator.check_yaml_content_rules(file_path, project_uses_secure_properties=True)
        self.assertTrue(any("Value for key 'credentials.encoded' appears to be a generic secret/API key" in issue for issue in issues))


    def test_yaml_clean_no_secrets(self):
        yaml_content_str = "server:\n  port: 8081\nconfig:\n  featureEnabled: true"
        file_path = self._write_temp_yaml_file("clean.yaml", content_str=yaml_content_str)
        issues = configfile_validator.check_yaml_content_rules(file_path, project_uses_secure_properties=True)
        self.assertEqual(len(issues), 0, f"Expected 0 issues for a clean YAML, got: {issues}")

    def test_empty_yaml_file_content_rules(self):
        file_path = self._write_temp_yaml_file("empty_content.yaml", content_str="")
        issues = configfile_validator.check_yaml_content_rules(file_path, project_uses_secure_properties=True)
        self.assertEqual(len(issues), 0, f"Expected 0 content issues for an empty YAML, got: {issues}")

    def test_yaml_with_only_comments_content_rules(self):
        file_path = self._write_temp_yaml_file("comments_only_content.yaml", content_str="# Comment\n# Another comment")
        issues = configfile_validator.check_yaml_content_rules(file_path, project_uses_secure_properties=True)
        self.assertEqual(len(issues), 0, f"Expected 0 content issues for a comments-only YAML, got: {issues}")

    def test_filename_recognition_no_warning(self):
        test_cases = {
            "keystore.jks": {"https.keystore.file": "eimulegen_keystore.jks"},
            "truststore.pem": {"ssl.truststore.path": "/var/certs/client.pem"},
        }
        for filename_value, content_dict in test_cases.items():
            with self.subTest(filename_value=filename_value):
                file_path = self._write_temp_yaml_file(f"test_{filename_value.replace('.', '_')}.yaml", content_dict=content_dict)
                issues_true = configfile_validator.check_yaml_content_rules(file_path, project_uses_secure_properties=True)
                self.assertEqual(len(issues_true), 0, f"Should not warn for {filename_value}. Issues: {issues_true}")

    def test_sensitive_key_non_filename_should_warn(self):
        yaml_content = {"credentials.password": "thisisaplainpassword"}
        file_path = self._write_temp_yaml_file("sensitive_non_filename.yaml", content_dict=yaml_content)
        issues_true = configfile_validator.check_yaml_content_rules(file_path, project_uses_secure_properties=True)
        self.assertTrue(any("contains sensitive keyword 'password'" in issue and "has a plaintext value" in issue for issue in issues_true))

    def test_suppress_info_for_encrypted_values(self):
        yaml_content = {"api.key": "![encryptedValue]"}
        file_path = self._write_temp_yaml_file("encrypted_values_info_suppressed.yaml", content_dict=yaml_content)
        issues = configfile_validator.check_yaml_content_rules(file_path, project_uses_secure_properties=True)
        self.assertEqual(len(issues), 0, f"Expected 0 issues for properly encrypted values. Got: {issues}")

    def test_warning_for_encrypted_value_if_secure_properties_not_used(self):
        yaml_content = {"database.password": "![encryptedPass]"}
        file_path = self._write_temp_yaml_file("encrypted_no_secure_props.yaml", content_dict=yaml_content)
        issues = configfile_validator.check_yaml_content_rules(file_path, project_uses_secure_properties=False)
        self.assertTrue(any("Key 'database.password' has a Mule encrypted value, but Mule Secure Properties configuration was not detected" in issue for issue in issues))

    def test_filename_context_skips_generic_secret_warning(self):
        long_path_like_value = "certs/ci/very-long-path-that-might-look-like-a-secret-abcdef1234567890abcdef1234567890.pem"
        content_dict = {"server.ssl.keyFile": long_path_like_value}
        file_path = self._write_temp_yaml_file("filename_ctx_generic.yaml", content_dict=content_dict)
        issues = configfile_validator.check_yaml_content_rules(file_path, project_uses_secure_properties=True)
        self.assertEqual(len(issues),0, f"Should not warn for generic secret due to filename context. Issues: {issues}")

    def test_filename_context_skips_sensitive_keyword_warning_for_path_values(self):
        content_dict = {"empDbSnowflake.keyFile": "configs/snowflake/prod_rsa.key"}
        file_path = self._write_temp_yaml_file("filename_ctx_keyword.yaml", content_dict=content_dict)
        issues = configfile_validator.check_yaml_content_rules(file_path, project_uses_secure_properties=True)
        self.assertEqual(len(issues),0, f"Should not warn for sensitive keyword due to filename context. Issues: {issues}")

    def test_sensitive_key_warns_if_value_not_path_despite_filename_key_suffix(self):
        content_dict = {"empDbSnowflake.keyFile": "THIS_IS_A_VERY_LONG_AND_OBVIOUS_SECRET_KEY_NOT_A_PATH_abcdef12345"}
        file_path = self._write_temp_yaml_file("filename_key_secret_value.yaml", content_dict=content_dict)
        issues = configfile_validator.check_yaml_content_rules(file_path, project_uses_secure_properties=True)
        self.assertTrue(any("appears to be a generic secret/API key" in issue for issue in issues))
        self.assertTrue(any("contains sensitive keyword 'key'" in issue for issue in issues)) # "key" in "keyFile"

    def test_check_yaml_content_rules_error_handling_bad_file(self):
        # Test how check_yaml_content_rules handles a non-existent file
        # It should return an error message within the list of issues.
        bad_file_path = os.path.join(self.test_dir, "this_file_does_not_exist.yaml")
        issues = configfile_validator.check_yaml_content_rules(bad_file_path, True)
        self.assertEqual(len(issues), 1)
        self.assertIn(f"ERROR: Could not read or parse YAML file {bad_file_path}", issues[0])

    def test_check_yaml_content_rules_malformed_yaml(self):
        file_path = self._write_temp_yaml_file("malformed_content.yaml", "key: value\n  bad_indent: oops")
        issues = configfile_validator.check_yaml_content_rules(file_path, True)
        self.assertEqual(len(issues), 1)
        self.assertIn(f"ERROR: Could not read or parse YAML file {file_path}", issues[0])
        self.assertIn("Error token:", issues[0]) # Check for part of the yaml.YAMLError message


class TestEnvironmentConfigComparison(unittest.TestCase):

    def test_get_common_keys_with_identical_values_simple(self):
        data1 = {"a": 1, "b": "same", "c": "diff1"}
        data2 = {"a": 2, "b": "same", "c": "diff2", "d": "only_in_2"}
        expected = ["b"]
        self.assertEqual(sorted(configfile_validator._get_common_keys_with_identical_values(data1, data2)), sorted(expected))

    def test_get_common_keys_with_identical_values_nested(self):
        data1 = {"user": {"name": "test", "email": "test@example.com"}, "host": "localhost", "port": 8080}
        data2 = {"user": {"name": "test", "email": "another@example.com"}, "host": "localhost", "port": 8081}
        expected = ["user.name", "host"]
        self.assertEqual(sorted(configfile_validator._get_common_keys_with_identical_values(data1, data2)), sorted(expected))

    # ... (other tests for _get_common_keys_with_identical_values remain the same) ...
    def test_get_common_keys_with_identical_values_no_common_identical(self):
        data1 = {"a": 1, "b": 2}
        data2 = {"a": "one", "b": "two"}
        self.assertEqual(configfile_validator._get_common_keys_with_identical_values(data1, data2), [])

    def test_get_common_keys_with_identical_values_empty_dicts(self):
        self.assertEqual(configfile_validator._get_common_keys_with_identical_values({}, {}), [])
        self.assertEqual(configfile_validator._get_common_keys_with_identical_values({"a": 1}, {}), [])

    def test_get_common_keys_with_identical_values_identical_lists(self):
        data1 = {"list_key": [1, 2, {"sub": "val"}]}
        data2 = {"list_key": [1, 2, {"sub": "val"}]}
        expected = ["list_key"]
        self.assertEqual(sorted(configfile_validator._get_common_keys_with_identical_values(data1, data2)), sorted(expected))

    def test_get_common_keys_with_identical_values_different_lists(self):
        data1 = {"list_key": [1, 2, 3]}
        data2 = {"list_key": [1, 2, 4]}
        self.assertEqual(configfile_validator._get_common_keys_with_identical_values(data1, data2), [])

    def test_get_common_keys_mixed_types_no_error(self):
        data1 = {"a": {"nested_a": 1}, "b": "string_val", "c": [1,2]}
        data2 = {"a": "string_val_instead_of_dict", "b": {"nested_b": 1}, "c": "string_val_instead_of_list"}
        self.assertEqual(configfile_validator._get_common_keys_with_identical_values(data1, data2), [])


    def test_compare_environment_config_values_detailed_scenarios(self):
        test_scenarios = [
            {
                "name": "Scenario 1: Identical values for TARGET_CONFIG_KEYWORDS field",
                "prod_data": {"db.host": "server1", "api.key": "secret123", "service.url": "http://service.com"},
                "nonprod_data": {"db.host": "server1", "api.key": "secret123", "service.url": "http://service.com"},
                "expected_warnings_containing": ["db.host", "api.key", "service.url"],
                "expected_warning_count": 3,
            },
            {
                "name": "Scenario 2: Different values for TARGET_CONFIG_KEYWORDS field",
                "prod_data": {"db.host": "prod_server", "user.password": "prod_pass"},
                "nonprod_data": {"db.host": "dev_server", "user.password": "dev_pass"},
                "expected_warnings_containing": [],
                "expected_warning_count": 0,
            },
            {
                "name": "Scenario 3: Identical values for non-TARGET_CONFIG_KEYWORDS field",
                "prod_data": {"ui.theme": "dark", "feature.flag": True},
                "nonprod_data": {"ui.theme": "dark", "feature.flag": True},
                "expected_warnings_containing": [],
                "expected_warning_count": 0,
            },
            {
                "name": "Scenario 4: Mixed - some identical target, some identical non-target, some different target",
                "prod_data": {"db.host": "common_server", "ui.color": "blue", "payment.endpoint": "http://prod.api"},
                "nonprod_data": {"db.host": "common_server", "ui.color": "blue", "payment.endpoint": "http://dev.api"},
                "expected_warnings_containing": ["db.host"], # "payment.endpoint" differs
                "expected_warning_count": 1,
            },
             { # Test for regex match on segment
                "name": "Scenario 5: Regex match for segment",
                "prod_data": {"connection.endpoint": "same_endpoint", "old.host.name": "same_host"},
                "nonprod_data": {"connection.endpoint": "same_endpoint", "old.host.name": "same_host"},
                "expected_warnings_containing": ["connection.endpoint", "old.host.name"],
                "expected_warning_count": 2,
            }
        ]

        for scenario in test_scenarios:
            with self.subTest(name=scenario["name"]):
                env_configs = {"prod": scenario["prod_data"], "nonprod": scenario["nonprod_data"]}
                issues = configfile_validator.compare_environment_config_values(env_configs)
                self.assertEqual(len(issues), scenario["expected_warning_count"], f"Scenario '{scenario['name']}' failed: Expected {scenario['expected_warning_count']} warnings, got {len(issues)}. Issues: {issues}")
                for expected_key_in_warning in scenario["expected_warnings_containing"]:
                    self.assertTrue(any(f"'{expected_key_in_warning}'" in issue_msg for issue_msg in issues),
                                    f"Scenario '{scenario['name']}' failed: Expected warning for key '{expected_key_in_warning}'. Issues: {issues}")

    def test_compare_environment_config_values_no_identical_relevant(self):
        prod_data = {"db.host": "prod_server"}
        nonprod_data = {"db.host": "nonprod_server"}
        env_configs = {"prod": prod_data, "nonprod": nonprod_data}
        issues = configfile_validator.compare_environment_config_values(env_configs)
        self.assertEqual(len(issues), 0)

    def test_compare_environment_config_values_one_env_missing(self):
        prod_data = {"db.host": "prod_server"}
        env_configs = {"prod": prod_data} # nonprod is missing
        issues = configfile_validator.compare_environment_config_values(env_configs)
        self.assertEqual(len(issues), 0)

    def test_compare_environment_config_values_one_env_empty(self):
        prod_data = {"db.host": "prod_server"}
        nonprod_data = {}
        env_configs = {"prod": prod_data, "nonprod": nonprod_data}
        issues = configfile_validator.compare_environment_config_values(env_configs)
        self.assertEqual(len(issues), 0)


class TestValidateFilesIntegration(unittest.TestCase):
    def setUp(self):
        self.test_dir = tempfile.mkdtemp()
        self.resources_path = os.path.join(self.test_dir, "src", "main", "resources")
        os.makedirs(self.resources_path, exist_ok=True)

    def tearDown(self):
        shutil.rmtree(self.test_dir)

    def _write_yaml(self, filepath, content_dict):
        with open(filepath, 'w') as f:
            yaml.dump(content_dict, f)

    @patch('mule_validator.configfile_validator.check_yaml_content_rules')
    @patch('mule_validator.configfile_validator.compare_environment_config_values')
    def test_validate_files_normal_run(self, mock_compare_env, mock_check_content):
        # Setup mock files
        self._write_yaml(os.path.join(self.resources_path, "config-prod.yaml"), {"db.host": "prod_host"})
        self._write_yaml(os.path.join(self.resources_path, "config-nonprod.yaml"), {"db.host": "dev_host"})
        self._write_yaml(os.path.join(self.resources_path, "config-dev.yaml"), {"db.host": "dev_host"})

        mock_check_content.return_value = ["content issue 1"] # Example content issue for each file
        mock_compare_env.return_value = ["env comparison issue 1"]

        results = configfile_validator.validate_files(self.test_dir, True)

        # Check for syntax validation results (should be 'Valid Syntax' for files created)
        self.assertTrue(any(r[0] == "config-prod.yaml" and r[1] == "Valid Syntax" for r in results))
        self.assertTrue(any(r[0] == "config-nonprod.yaml" and r[1] == "Valid Syntax" for r in results))
        self.assertTrue(any(r[0] == "config-dev.yaml" and r[1] == "Valid Syntax" for r in results))

        # Check for content issues (mocked to return "content issue 1" for each valid file)
        # 3 files are valid, so 3 content issues expected from the mock
        self.assertEqual(sum(1 for r in results if r[1] == 'Content Issue' and r[2] == 'content issue 1'), 3)

        # Check for environment comparison issues
        self.assertTrue(any(r[1] == 'Environment Config Value Issue' and r[2] == 'env comparison issue 1' for r in results))

        self.assertEqual(mock_check_content.call_count, 3) # Called for prod, nonprod, dev
        mock_compare_env.assert_called_once()


    def test_validate_files_missing_mandatory(self):
        # Only create one mandatory file
        self._write_yaml(os.path.join(self.resources_path, "config-prod.yaml"), {"key": "value"})

        with patch('mule_validator.configfile_validator.check_yaml_content_rules', return_value=[]):
            results = configfile_validator.validate_files(self.test_dir, True)

        self.assertTrue(any(r[0] == "config-nonprod.yaml" and r[1] == "Missing" for r in results))
        self.assertTrue(any(r[0] == "config-prod.yaml" and r[1] == "Valid Syntax" for r in results))

    def test_validate_files_invalid_syntax_mandatory(self):
        invalid_yaml_path = os.path.join(self.resources_path, "config-prod.yaml")
        with open(invalid_yaml_path, 'w') as f:
            f.write("key: value\n bad_indent: oops") # Invalid YAML

        with patch('mule_validator.configfile_validator.check_yaml_content_rules', return_value=[]):
            results = configfile_validator.validate_files(self.test_dir, True)

        self.assertTrue(any(r[0] == "config-prod.yaml" and r[1] == "Invalid Syntax" for r in results))
        # check_yaml_content_rules should not be called for config-prod.yaml
        # Let's verify by checking its call args if it was called multiple times for other files
        mock_check_content_calls = configfile_validator.check_yaml_content_rules.call_args_list
        for call_arg in mock_check_content_calls:
            self.assertNotEqual(call_arg[0][0], invalid_yaml_path)


    def test_validate_files_resources_dir_missing(self):
        # test_dir itself does not contain src/main/resources
        results = configfile_validator.validate_files(self.test_dir + "/non_existent_project_root", True)
        self.assertEqual(len(results), 1)
        self.assertEqual(results[0][1], "Directory Missing")
        self.assertTrue("Resources directory not found" in results[0][2])


if __name__ == '__main__':
    unittest.main(verbosity=2)
