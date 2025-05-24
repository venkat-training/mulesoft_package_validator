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

if __name__ == '__main__':
    unittest.main(verbosity=2)
