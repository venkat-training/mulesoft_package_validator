# mule_validator/security_patterns.py
"""
Defines lists of keywords and regular expression patterns for detecting secrets.

This module centralizes the definitions of various patterns used across the
Mule Validator project to identify potential hardcoded secrets such as passwords,
API keys, tokens, and other sensitive credentials within configuration files (YAML, XML),
POM files, and potentially other scanned resources.

The patterns are categorized into keywords (for identifying sensitive field names or tags)
and value patterns (for identifying sensitive data formats directly).
"""
import re

# Keywords that often indicate a property or XML tag is for a password or similar credential.
PASSWORD_KEYWORDS = [
    "password",
    "pass",
    "pwd",
    "secret", # Broad, but often used for passwords
    "credential",
    "credentials"
]

# Regex patterns designed to match common, weak, or default password *values*.
# These should typically be applied with case-insensitivity (e.g., re.IGNORECASE).
COMMON_PASSWORD_PATTERNS = [
    r"^(password|admin|root|12345|qwerty|secret|passphrase)$", # Simple common passwords
    # Add more if any come to mind that are very common defaults
]

# Keywords that often indicate a property or XML tag is for a generic secret,
# such as an API key, access token, or other non-password credential.
GENERIC_SECRET_KEYWORDS = [
    "apikey",
    "api_key",
    "secretkey",
    "secret_key",
    "accesstoken",
    "access_token",
    "clientsecret",
    "client_secret",
    "privatekey",
    "private_key",
    "encryptionkey",
    "encryption_key",
    "token", # Generic token
    "bearer", # For bearer tokens
    "authorization" # For authorization headers/values that might contain secrets
]

# Regex patterns designed to match the *values* of common secret formats.
# These patterns identify strings that look like API keys, tokens, or other encoded secrets.
GENERIC_SECRET_VALUE_PATTERNS = [
    r"[a-zA-Z0-9+/=]{32,}", # Base64-like strings, common for tokens (min length 32)
    r"ey[A-Za-z0-9_-]{20,}\.[A-Za-z0-9_-]{20,}\.(?:[A-Za-z0-9_-]{20,})?", # JWT-like pattern (more flexible)
    r"(?:sk|pk)_(?:test|live)_[0-9a-zA-Z]{10,}", # Stripe-like API keys
    r"AIza[0-9A-Za-z\-_]{35}", # Google API Key like pattern
    r"AKIA[0-9A-Z]{16}", # AWS Access Key ID like pattern
    r"[a-zA-Z0-9]{40}", # Potential SHA1 hash (e.g., Git commit hash, some API keys)
    # Basic hex string detection (could be part of a broader check if combined with context).
    # A very generic pattern for a string that contains at least one digit, one uppercase, one lowercase,
    # and is longer than 8 characters.
    # WARNING: This pattern ("strong password" like) is highly prone to false positives if used broadly
    # without strong contextual keywords. It's commented out to prevent accidental misuse
    # but retained as an example of a more complex, potentially problematic pattern.
    # r"^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)[a-zA-Z\d\S]{8,}$"
]

# General Note on Regex Usage:
# It's good practice to pre-compile regular expressions (using re.compile())
# if they are used multiple times, for example, in loops or frequently called functions.
# This is typically done in the modules where these patterns are actively used,
# or a utility function could be added here to provide compiled versions.
# For now, they are defined as raw strings for clarity and centralization.
# Ensure re.IGNORECASE is used where appropriate when compiling these patterns.
