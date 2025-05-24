# mule_validator/security_patterns.py
import re

PASSWORD_KEYWORDS = [
    "password",
    "pass",
    "pwd",
    "secret", # Broad, but often used for passwords
    "credential",
    "credentials"
]

# Regexes to be compiled with re.IGNORECASE if used directly,
# or ensure case-insensitivity in how they are applied.
COMMON_PASSWORD_PATTERNS = [
    r"^(password|admin|root|12345|qwerty|secret|passphrase)$", # Simple common passwords
    # Add more if any come to mind that are very common defaults
]

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

# These patterns are for the values themselves.
GENERIC_SECRET_VALUE_PATTERNS = [
    r"[a-zA-Z0-9+/=]{32,}", # Base64-like strings, common for tokens (min length 32)
    r"ey[A-Za-z0-9_-]{20,}\.[A-Za-z0-9_-]{20,}\.(?:[A-Za-z0-9_-]{20,})?", # JWT-like, more flexible
    r"(?:sk|pk)_(?:test|live)_[0-9a-zA-Z]{10,}", # Stripe-like keys
    r"AIza[0-9A-Za-z\-_]{35}", # Google API Key like
    r"AKIA[0-9A-Z]{16}", # AWS Access Key ID like
    r"[a-zA-Z0-9]{40}", # Potential SHA1 hash (e.g., Git commit, some API keys)
    # Basic hex string detection, could be part of a broader check
    # A simple check for a string that contains at least one digit, one uppercase, one lowercase, and is > 8 chars
    # This one is VERY generic and might lead to false positives if not used carefully with keyword checks.
    # r"^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)[a-zA-Z\d\S]{8,}$" # Example of a "strong password" like pattern
]

# It's good practice to pre-compile regexes if they are used many times,
# but for now, defining them as strings is fine for this file.
# If pre-compilation is desired, it can be done in the modules that use them
# or by adding a function here that returns compiled versions.
