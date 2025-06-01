import unittest
import os
import tempfile
import shutil
import yaml # For creating test files

from mule_validator.configfile_validator import validate_yaml_file
# No longer need MANDATORY_CONFIG_FILES, OPTIONAL_CONFIG_FILES, RESOURCES_PATH_NAME for these unit tests
# as we are directly testing validate_yaml_file with controlled content.

# Temporarily suppress logging from the validator module to keep test output clean
import logging
logging.getLogger('mule_validator.configfile_validator').setLevel(logging.CRITICAL)

# Import the function actually modified and tested
from mule_validator.configfile_validator import check_yaml_content_rules

class TestConfigFileValidatorSecurity(unittest.TestCase):

    def setUp(self):
        self.test_dir = tempfile.mkdtemp()
        # We are writing files directly to test_dir for validate_yaml_file tests
        # No need for a nested 'src/main/resources' structure here as validate_yaml_file takes a direct path.

    def tearDown(self):
        shutil.rmtree(self.test_dir)

    def _write_temp_yaml_file(self, filename, content_dict=None, content_str=None):
        file_path = os.path.join(self.test_dir, filename)
        with open(file_path, 'w', encoding='utf-8') as f:
            if content_dict is not None:
                yaml.dump(content_dict, f, sort_keys=False) # sort_keys=False to maintain order for easier assertion if needed
            elif content_str is not None:
                f.write(content_str)
            else:
                raise ValueError("Either content_dict or content_str must be provided")
        return file_path

    def test_yaml_with_keyword_secret(self):
        yaml_content = {
            "user": {
                "name": "testuser",
                "password": "actual_password123" # Keyword "password"
            },
            "api_access":{
                "key": "somekey",
                "secretkey": "thisIsASecretKey123!" # Keyword "secretkey"
            }
        }
        file_path = self._write_temp_yaml_file("keyword_secret.yaml", content_dict=yaml_content)
        results = validate_yaml_file(file_path)
        
        self.assertTrue(any(r['status'] == 'SecurityWarning' for r in results), "Should raise a SecurityWarning")
        
        password_warning_found = False
        secretkey_warning_found = False
        for r in results:
            if r['status'] == 'SecurityWarning':
                self.assertEqual(r['file_name'], file_path)
                details = r.get('details', {})
                if details.get('path') == "user.password" and "matches a password keyword" in details.get('message', ''):
                    password_warning_found = True
                    self.assertEqual(details.get('key'), "password")
                    self.assertTrue(details.get('value_excerpt', '').startswith("actual_password123"))
                if details.get('path') == "api_access.secretkey" and "matches a generic secret keyword" in details.get('message', ''):
                    secretkey_warning_found = True
                    self.assertEqual(details.get('key'), "secretkey")
                    self.assertTrue(details.get('value_excerpt', '').startswith("thisIsASecretKey123!"))
        
        self.assertTrue(password_warning_found, "Keyword 'password' warning not found or incorrect.")
        self.assertTrue(secretkey_warning_found, "Keyword 'secretkey' warning not found or incorrect.")

    def test_yaml_with_value_pattern_secret(self):
        jwt_token = "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c"
        yaml_content_str = f"settings:\n  token: {jwt_token}\n  another_setting: some_value"
        file_path = self._write_temp_yaml_file("value_pattern_secret.yaml", content_str=yaml_content_str)
        results = validate_yaml_file(file_path)

        self.assertTrue(any(r['status'] == 'SecurityWarning' for r in results), "Should raise a SecurityWarning for JWT token")
        
        jwt_warning_found = False
        for r in results:
            if r['status'] == 'SecurityWarning':
                details = r.get('details', {})
                if details.get('path') == 'settings.token' and "matches generic secret pattern" in details.get('message', ''):
                    self.assertTrue(details.get('value_excerpt', '').startswith("eyJhbGciOiJIUzI1NiJ9"))
                    self.assertEqual(details.get('key'), "token")
                    jwt_warning_found = True
        self.assertTrue(jwt_warning_found, "JWT pattern warning not found or incorrect.")

    def test_yaml_with_common_password_value(self):
        yaml_content_str = "config:\n  default_user: admin" # Common password pattern
        file_path = self._write_temp_yaml_file("common_password.yaml", content_str=yaml_content_str)
        results = validate_yaml_file(file_path)
        self.assertTrue(any(r['status'] == 'SecurityWarning' for r in results), "Should raise a SecurityWarning for common password")

        admin_warning_found = False
        for r in results:
            if r['status'] == 'SecurityWarning':
                details = r.get('details', {})
                if details.get('path') == 'config.default_user' and "matches common password pattern" in details.get('message', ''):
                    self.assertEqual(details.get('key'), "default_user")
                    self.assertTrue(details.get('value_excerpt', '').startswith("admin"))
                    admin_warning_found = True
        self.assertTrue(admin_warning_found, "Common password 'admin' warning not found.")

    def test_yaml_clean_no_secrets(self):
        yaml_content_str = "server:\n  port: 8081"
        file_path = self._write_temp_yaml_file("clean.yaml", content_str=yaml_content_str)
        results = validate_yaml_file(file_path)
        
        security_warnings = [r for r in results if r['status'] == 'SecurityWarning']
        self.assertEqual(len(security_warnings), 0, f"Expected 0 security warnings for a clean YAML, got: {results}")
        # A clean file might still have other status if it's empty or fails other non-security checks,
        # but for this test, we focus on no *security* warnings.
        # The current validate_yaml_file returns an empty list if no issues at all.
        if not results: # If results is empty, it's valid and no secrets.
            pass
        else: # If results is not empty, ensure no security warnings.
            self.assertFalse(any(r['status'] == 'SecurityWarning' for r in results), 
                             f"Clean YAML should not produce security warnings. Got: {results}")


    def test_yaml_invalid_syntax(self):
        invalid_yaml_str = "server: port: 8081" # No colon for server, invalid
        file_path = self._write_temp_yaml_file("invalid_syntax.yaml", content_str=invalid_yaml_str)
        results = validate_yaml_file(file_path)

        self.assertTrue(len(results) >= 1, "Should return at least one issue for invalid syntax.")
        self.assertEqual(results[0]['status'], 'InvalidSyntax')
        self.assertEqual(results[0]['file_name'], file_path)
        self.assertTrue("Invalid YAML syntax" in results[0]['message'])
    
    def test_yaml_file_not_found(self):
        results = validate_yaml_file(os.path.join(self.test_dir, "non_existent_file.yaml"))
        self.assertEqual(len(results), 1)
        self.assertEqual(results[0]['status'], 'Error')
        self.assertTrue("Error opening or reading file" in results[0]['message'])

    def test_empty_yaml_file(self):
        file_path = self._write_temp_yaml_file("empty.yaml", content_str="")
        results = validate_yaml_file(file_path)
        self.assertEqual(len(results), 0, f"Expected 0 issues for an empty YAML, got: {results}")

    def test_yaml_with_only_comments(self):
        file_path = self._write_temp_yaml_file("comments_only.yaml", content_str="# This is a comment\n# So is this")
        results = validate_yaml_file(file_path)
        self.assertEqual(len(results), 0, f"Expected 0 issues for a comments-only YAML, got: {results}")

    # New tests for check_yaml_content_rules related to recent changes

    def test_filename_recognition_no_warning(self):
        """Test that values resembling filenames with sensitive keywords in key are not warned."""
        test_cases = {
            "keystore.jks": {"https.keystore.file": "eimulegen_keystore.jks"},
            "truststore.pem": {"ssl.truststore.path": "/var/certs/client.pem"},
            "certificate.cer": {"tls.certificate": "my_company.cer"},
            "privatekey.p12": {"client.auth.key": "path/to/pk.p12"},
            "some.properties": {"app.config.file": "override.properties"},
        }
        for filename_value, content_dict in test_cases.items():
            file_path = self._write_temp_yaml_file(f"test_{filename_value.replace('.', '_')}.yaml", content_dict=content_dict)

            # Test with project_uses_secure_properties = True
            issues_true = check_yaml_content_rules(file_path, project_uses_secure_properties=True)
            for issue in issues_true:
                self.assertNotIn("contains sensitive keyword", issue,
                                 f"Should not warn for {filename_value} when project_uses_secure_properties=True. Issue: {issue}")

            # Test with project_uses_secure_properties = False
            issues_false = check_yaml_content_rules(file_path, project_uses_secure_properties=False)
            for issue in issues_false:
                self.assertNotIn("may contain plaintext sensitive data", issue,
                                 f"Should not warn for {filename_value} when project_uses_secure_properties=False. Issue: {issue}")
                self.assertNotIn("contains sensitive keyword", issue, # General check
                                 f"Should not warn for {filename_value} when project_uses_secure_properties=False. Issue: {issue}")


    def test_sensitive_key_non_filename_should_warn(self):
        """Test that a sensitive key with a non-filename value still warns."""
        yaml_content = {"credentials.password": "thisisaplainpassword"}
        file_path = self._write_temp_yaml_file("sensitive_non_filename.yaml", content_dict=yaml_content)

        issues_true = check_yaml_content_rules(file_path, project_uses_secure_properties=True)
        self.assertTrue(any("contains sensitive keyword 'password'" in issue and "has a plaintext value" in issue for issue in issues_true),
                        f"Expected warning for plaintext password with secure properties enabled. Issues: {issues_true}")

        issues_false = check_yaml_content_rules(file_path, project_uses_secure_properties=False)
        self.assertTrue(any("contains sensitive keyword 'password'" in issue and "may contain plaintext sensitive data" in issue for issue in issues_false),
                        f"Expected warning for plaintext password with secure properties disabled. Issues: {issues_false}")

    def test_suppress_info_for_encrypted_values(self):
        """Test that INFO messages for Mule encrypted values are suppressed."""
        yaml_content = {"api.key": "![encryptedValue]", "user.token": "![anotherEncryptedValue]"}
        file_path = self._write_temp_yaml_file("encrypted_values_info_suppressed.yaml", content_dict=yaml_content)

        issues = check_yaml_content_rules(file_path, project_uses_secure_properties=True)
        for issue in issues:
            self.assertNotIn("INFO: Key", issue, f"INFO message for encrypted value should be suppressed. Got: {issue}")

        # Sanity check: ensure no other unexpected warnings for these keys
        self.assertEqual(len(issues), 0, f"Expected 0 issues for properly encrypted values with info suppressed. Got: {issues}")


    def test_warning_for_encrypted_value_if_secure_properties_not_used(self):
        """Test that a WARNING is issued for encrypted values if project does not use secure properties."""
        yaml_content = {"database.password": "![encryptedPass]", "service.secret": "![someSecretDataValue]"}
        file_path = self._write_temp_yaml_file("encrypted_values_warning_no_secure_props.yaml", content_dict=yaml_content)

        issues = check_yaml_content_rules(file_path, project_uses_secure_properties=False)

        password_warning_found = any("WARNING: Key 'database.password' has a Mule encrypted value, but Mule Secure Properties configuration was not detected project-wide." in issue for issue in issues)
        secret_warning_found = any("WARNING: Key 'service.secret' has a Mule encrypted value, but Mule Secure Properties configuration was not detected project-wide." in issue for issue in issues)

        self.assertTrue(password_warning_found, f"Missing expected WARNING for database.password. Issues: {issues}")
        self.assertTrue(secret_warning_found, f"Missing expected WARNING for service.secret. Issues: {issues}")

        # Ensure no INFO messages are present
        for issue in issues:
            self.assertNotIn("INFO: Key", issue, f"INFO message for encrypted value should be suppressed even if warning. Got: {issue}")

        self.assertEqual(len(issues), 2, f"Expected exactly 2 warnings. Got: {issues}")

    def test_filename_context_skips_generic_secret_warning(self):
        """Test that generic secret warnings are skipped for keys/values in filename context."""
        # This value would normally trigger GENERIC_SECRET_PATTERN
        long_path_like_value = "certs/ci/very-long-path-that-might-look-like-a-secret-abcdef1234567890abcdef1234567890.pem"

        test_cases = [
            # Key suggests filename
            ({"server.ssl.keyFile": long_path_like_value}, "server.ssl.keyFile"),
            ({"truststore.path.filename": long_path_like_value}, "truststore.path.filename"),
            # Value suggests filename/path
            ({"some.random.key": "path/to/my_very_long_secret_looking_file_name_that_is_a_path.key"}, "some.random.key"),
            ({"another.key": "classpath:/config/secrets/a_very_long_secret_looking_classpath_resource.properties"}, "another.key"),
        ]

        for content_dict, key_tested in test_cases:
            file_path = self._write_temp_yaml_file(f"test_filename_ctx_generic_{key_tested.replace('.', '_')}.yaml", content_dict=content_dict)
            issues_true = check_yaml_content_rules(file_path, project_uses_secure_properties=True)
            issues_false = check_yaml_content_rules(file_path, project_uses_secure_properties=False)

            for issue in issues_true + issues_false:
                self.assertNotIn("appears to be a generic secret/API key", issue,
                                 f"Should not warn for generic secret on key '{key_tested}' due to filename context. Issue: {issue}")

    def test_filename_context_skips_sensitive_keyword_warning_for_path_values(self):
        """Test that sensitive keyword warnings are skipped if key/value indicates a path."""
        test_cases = [
            # Key "empDbSnowflake.keyFile" contains "key", value is a path
            ({"empDbSnowflake.keyFile": "configs/snowflake/prod_rsa.key"}, "empDbSnowflake.keyFile"),
            # Key "api.tokenFile" contains "token", value is a path
            ({"api.tokenFile": "/etc/secrets/api-token.txt"}, "api.tokenFile"),
            # Key "credentials.file" contains "credentials", value is a path
            ({"credentials.file": "classpath:/secure/auth.properties"}, "credentials.file"),
        ]
        for content_dict, key_tested in test_cases:
            file_path = self._write_temp_yaml_file(f"test_filename_ctx_keyword_{key_tested.replace('.', '_')}.yaml", content_dict=content_dict)
            issues_true = check_yaml_content_rules(file_path, project_uses_secure_properties=True)
            issues_false = check_yaml_content_rules(file_path, project_uses_secure_properties=False)

            for issue in issues_true + issues_false:
                self.assertNotIn("contains sensitive keyword", issue,
                                 f"Should not warn for sensitive keyword on key '{key_tested}' due to filename context with path value. Issue: {issue}")
                self.assertNotIn("may contain plaintext sensitive data", issue,
                                 f"Should not warn for sensitive keyword on key '{key_tested}' due to filename context with path value. Issue: {issue}")

    def test_sensitive_key_warns_if_value_not_path_despite_filename_key_suffix(self):
        """Test that a key like *.keyFile still warns if its value is not a path but a secret."""
        # Key "empDbSnowflake.keyFile" suggests a filename, but the value is a direct secret
        content_dict = {"empDbSnowflake.keyFile": "THIS_IS_A_VERY_LONG_AND_OBVIOUS_SECRET_KEY_NOT_A_PATH_abcdef12345"}
        key_tested = "empDbSnowflake.keyFile"
        file_path = self._write_temp_yaml_file(f"test_filename_key_secret_value_{key_tested.replace('.', '_')}.yaml", content_dict=content_dict)

        # Expect GENERIC_SECRET_PATTERN to catch this, as it's not a filename context if value is not path-like
        issues = check_yaml_content_rules(file_path, project_uses_secure_properties=True)
        self.assertTrue(
            any("appears to be a generic secret/API key" in issue and key_tested in issue for issue in issues),
            f"Expected generic secret warning for '{key_tested}' when value is a secret, not a path. Issues: {issues}"
        )

        # SENSITIVE_KEYWORD check should also apply because the value is not path-like,
        # thus `is_filename_context` becomes false.
        # The keyword "key" is in "empDbSnowflake.keyFile".
        self.assertTrue(
            any("contains sensitive keyword 'key'" in issue and key_tested in issue for issue in issues),
            f"Expected sensitive keyword warning for '{key_tested}' when value is a secret. Issues: {issues}"
        )


# More tests might be needed for validate_files and the new comparison logic.
# For now, focusing on check_yaml_content_rules updates.

from mule_validator.configfile_validator import (
    _get_common_keys_with_identical_values,
    compare_environment_config_values,
    validate_files # For integration testing
)
from unittest.mock import patch, mock_open, MagicMock

class TestEnvironmentConfigComparison(unittest.TestCase):

    def test_get_common_keys_with_identical_values_simple(self):
        data1 = {"a": 1, "b": "same", "c": "diff1"}
        data2 = {"a": 2, "b": "same", "c": "diff2", "d": "only_in_2"}
        expected = ["b"]
        self.assertEqual(sorted(_get_common_keys_with_identical_values(data1, data2)), sorted(expected))

    def test_get_common_keys_with_identical_values_nested(self):
        data1 = {"user": {"name": "test", "email": "test@example.com"}, "host": "localhost", "port": 8080}
        data2 = {"user": {"name": "test", "email": "another@example.com"}, "host": "localhost", "port": 8081}
        expected = ["user.name", "host"]
        self.assertEqual(sorted(_get_common_keys_with_identical_values(data1, data2)), sorted(expected))

    def test_get_common_keys_with_identical_values_no_common_identical(self):
        data1 = {"a": 1, "b": 2}
        data2 = {"a": "one", "b": "two"}
        self.assertEqual(_get_common_keys_with_identical_values(data1, data2), [])

    def test_get_common_keys_with_identical_values_empty_dicts(self):
        self.assertEqual(_get_common_keys_with_identical_values({}, {}), [])
        self.assertEqual(_get_common_keys_with_identical_values({"a": 1}, {}), [])

    def test_get_common_keys_with_identical_values_identical_lists(self):
        data1 = {"list_key": [1, 2, {"sub": "val"}]}
        data2 = {"list_key": [1, 2, {"sub": "val"}]}
        expected = ["list_key"]
        self.assertEqual(sorted(_get_common_keys_with_identical_values(data1, data2)), sorted(expected))

    def test_get_common_keys_with_identical_values_different_lists(self):
        data1 = {"list_key": [1, 2, 3]}
        data2 = {"list_key": [1, 2, 4]}
        self.assertEqual(_get_common_keys_with_identical_values(data1, data2), [])

    def test_get_common_keys_mixed_types_no_error(self):
        data1 = {"a": {"nested_a": 1}, "b": "string_val", "c": [1,2]}
        data2 = {"a": "string_val_instead_of_dict", "b": {"nested_b": 1}, "c": "string_val_instead_of_list"}
        # No common keys should be found as identical because their types differ at the common key level
        self.assertEqual(_get_common_keys_with_identical_values(data1, data2), [])


    def test_compare_environment_config_values_prod_vs_nonprod(self):
        prod_data = {"db": {"host": "prod_db", "port": 5432}, "api": {"key": "prod_key", "timeout": 30}, "common_setting": "same_value"}
        nonprod_data = {"db": {"host": "nonprod_db", "port": 5432}, "api": {"key": "nonprod_key", "timeout": 30}, "common_setting": "same_value"}

        env_configs = {"prod": prod_data, "nonprod": nonprod_data}
        issues = compare_environment_config_values(env_configs)

        self.assertEqual(len(issues), 2) # db.port and common_setting and api.timeout
        self.assertTrue(any("Key 'db.port' has the same value" in issue for issue in issues))
        self.assertTrue(any("Key 'common_setting' has the same value" in issue for issue in issues))
        self.assertTrue(any("Key 'api.timeout' has the same value" in issue for issue in issues))

    def test_compare_environment_config_values_no_identical(self):
        prod_data = {"setting1": "prod_val"}
        nonprod_data = {"setting1": "nonprod_val"}
        env_configs = {"prod": prod_data, "nonprod": nonprod_data}
        issues = compare_environment_config_values(env_configs)
        self.assertEqual(len(issues), 0)

    def test_compare_environment_config_values_one_env_missing(self):
        prod_data = {"setting1": "prod_val"}
        env_configs = {"prod": prod_data} # nonprod is missing
        issues = compare_environment_config_values(env_configs)
        self.assertEqual(len(issues), 0)

    def test_compare_environment_config_values_one_env_empty(self):
        prod_data = {"setting1": "prod_val"}
        nonprod_data = {} # nonprod data is empty
        env_configs = {"prod": prod_data, "nonprod": nonprod_data}
        issues = compare_environment_config_values(env_configs)
        self.assertEqual(len(issues), 0) # No common keys to compare effectively

    @patch('mule_validator.configfile_validator.check_yaml_content_rules', MagicMock(return_value=[]))
    @patch('mule_validator.configfile_validator.validate_yaml_file', MagicMock(return_value=(True, None)))
    @patch('os.path.isdir', MagicMock(return_value=True))
    def test_validate_files_integration_with_env_comparison(self):
        # Mock file contents for prod and nonprod
        prod_yaml_content = "key1: value1\ncommon_key: same_value\ndb.host: prod_server"
        nonprod_yaml_content = "key2: value2\ncommon_key: same_value\ndb.host: nonprod_server"

        # Use a dictionary to map file paths to their content for mock_open
        # Need to ensure these paths are exactly what os.path.join(resources_folder_path, file_name) would produce.
        # Let package_folder_path be 'dummy_package'
        base_path = os.path.join('dummy_package', 'src', 'main', 'resources')
        mock_files = {
            os.path.join(base_path, 'config-prod.yaml'): prod_yaml_content,
            os.path.join(base_path, 'config-nonprod.yaml'): nonprod_yaml_content,
            os.path.join(base_path, 'config-dev.yaml'): "key_dev: val_dev", # Optional file
        }

        # Mock os.path.isfile to return True only for files in our mock_files dict
        def mock_isfile(path):
            return path in mock_files

        # The mock_open needs to handle multiple file opens correctly.
        # We can achieve this by making `mock_open.return_value.read.side_effect` dynamic.
        # However, yaml.safe_load is called inside validate_files.
        # A simpler way for this test is to mock yaml.safe_load directly.

        def mock_yaml_safe_load(stream):
            # Find which file content to return based on the stream's name attribute if available
            # This is a bit fragile as it depends on how `open` is called and if `name` is set.
            # A more robust mock might be needed if `stream.name` is not reliable.
            # For now, let's assume `stream` is the file object from `with open(...)`
            # and its `name` attribute holds the path.
            path_opened = stream.name
            if path_opened == os.path.join(base_path, 'config-prod.yaml'):
                return yaml.safe_load(prod_yaml_content)
            if path_opened == os.path.join(base_path, 'config-nonprod.yaml'):
                return yaml.safe_load(nonprod_yaml_content)
            if path_opened == os.path.join(base_path, 'config-dev.yaml'):
                return yaml.safe_load("key_dev: val_dev")
            return {} # Default empty dict for other files

        with patch('os.path.isfile', side_effect=mock_isfile):
            # We need to mock `open` because `validate_files` opens the file itself
            # to pass to `yaml.safe_load` for populating `parsed_env_configs_data`.
            # `check_yaml_content_rules` also opens files, but it's mocked.
            # `validate_yaml_file` also opens files, also mocked.
            # The `open` inside `validate_files` for `parsed_env_configs_data` is the one to target.
            m = mock_open()
            with patch('builtins.open', m) as mocked_open:
                # Configure the mock_open to return appropriate content based on file path
                def read_side_effect(*args, **kwargs):
                    filepath_arg = args[0]
                    if filepath_arg in mock_files:
                        return mock_files[filepath_arg]
                    return "" # Default empty content

                # Set up the file path correctly in the mocked open file object
                def new_mock_open(path, *args, **kwargs):
                    file_content = mock_files.get(path, "")
                    mock_file_obj = mock_open(read_data=file_content).return_value
                    mock_file_obj.name = path # Set the name attribute
                    return mock_file_obj

                mocked_open.side_effect = new_mock_open

                # Call the function under test
                results = validate_files('dummy_package', project_uses_secure_properties=True)

        # Assertions
        # Check for the specific comparison issue
        env_issue_found = False
        for result in results:
            if result[1] == 'Environment Config Value Issue':
                self.assertEqual(result[0], "Prod vs NonProd Comparison")
                self.assertTrue("Key 'common_key' has the same value" in result[2])
                env_issue_found = True
                break
        self.assertTrue(env_issue_found, "Environment comparison issue for 'common_key' not found.")

        # Check that normal file validation statuses are also present
        self.assertTrue(any(r[0] == 'config-prod.yaml' and r[1] == 'Valid Syntax' for r in results))
        self.assertTrue(any(r[0] == 'config-nonprod.yaml' and r[1] == 'Valid Syntax' for r in results))
        self.assertTrue(any(r[0] == 'config-dev.yaml' and r[1] == 'Valid Syntax' for r in results))

        # Ensure no errors from the mocked loading itself for env comparison
        self.assertFalse(any("ERROR: Could not load/parse" in r[2] for r in results if r[1] == 'Content Issue'))


if __name__ == '__main__':
    unittest.main(verbosity=2)
