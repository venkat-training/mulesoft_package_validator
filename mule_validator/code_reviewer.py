import os
from lxml import etree
import re
import logging
from mule_validator.security_patterns import (
    PASSWORD_KEYWORDS,
    COMMON_PASSWORD_PATTERNS,
    GENERIC_SECRET_KEYWORDS,
    GENERIC_SECRET_VALUE_PATTERNS
)

# Configure logging
logger = logging.getLogger(__name__)

# --- Security Related Constants ---
# Pre-compile regexes and prepare keywords for secrets
COMPILED_COMMON_PASSWORD_PATTERNS = [re.compile(p, re.IGNORECASE) for p in COMMON_PASSWORD_PATTERNS]
COMPILED_GENERIC_SECRET_VALUE_PATTERNS = [re.compile(p, re.IGNORECASE) for p in GENERIC_SECRET_VALUE_PATTERNS]
LOWERCASE_PASSWORD_KEYWORDS = [k.lower() for k in PASSWORD_KEYWORDS]
LOWERCASE_GENERIC_SECRET_KEYWORDS = [k.lower() for k in GENERIC_SECRET_KEYWORDS]

SECURE_PROPERTY_PATTERNS = [
    re.compile(r"^\s*\${secure::.+?}\s*$"),
    re.compile(r"^\s*p\('secure::.+?'\)\s*$"),
    re.compile(r"^\s*\{\{secure::.+?\}\}\s*$"), # Common in properties files, might appear in XML
    re.compile(r"^\s*\[dw://secure::.+?\]\s*$"), # DW secure properties
]

# SENSITIVE_MULE_ATTRIBUTES: keys are `prefix:localname` or just `localname` (if no common prefix or for global configs)
# It's better to use the `prefix:localname` format for namespaced elements to be more specific.
# For elements that might not always have a clear prefix in all Mule versions or usage patterns (e.g. global elements),
# using just localname might be an option, but can lead to more false positives if not carefully managed.
# The key for SENSITIVE_MULE_ATTRIBUTES should match how get_element_identifier_for_sens_check is constructed.
SENSITIVE_MULE_ATTRIBUTES = {
    # Database Connector (common prefixes: db, spring, etc. for config)
    'db:config': ['password'], 'spring:property_db_password': ['value'], # Example if spring bean for db pass
    'db:mssql-config': ['password'],
    'db:oracle-config': ['password'],
    'db:mysql-config': ['password'],
    # HTTP Requester
    'http:request-connection': ['password', 'proxyPassword', 'keyPassword', 'trustStorePassword', 'clientSecret'],
    'http:basic-authentication': ['password'], # direct child of http:authentication
    'http:ntlm-authentication': ['password'],
    'http:oauth-authorization-code-grant-type': ['clientSecret'],
    'http:oauth-client-credentials-grant-type': ['clientSecret'],
    'http:oauth-password-grant-type': ['clientSecret', 'password'],
    'http:oauth-custom-grant-type': ['clientSecret'], # and other params
    # SFTP/FTP Connectors
    'sftp:config': ['password', 'privateKeyPassphrase', 'keyPassword'], # SFTP config element
    'ftp:config': ['password'], # FTP config element
    # Email (common prefix: email, mail)
    'email:smtp-config': ['password'],
    'email:pop3-config': ['password'],
    'email:imap-config': ['password'],
    # JMS (common prefix: jms)
    'jms:config': ['password'], # General JMS config
    'jms:connection': ['password'], # If connection is defined directly
    'jms:xa-connection-factory': ['password'],
    # Salesforce
    'salesforce:config': ['password', 'securityToken', 'consumerSecret', 'privateKey'],
    'salesforce:basic-connection': ['password', 'securityToken'],
    'salesforce:oauth-jwt-connection': ['consumerSecret', 'privateKey'],
    'salesforce:oauth-user-pass-connection': ['consumerPassword', 'consumerSecret'],
    # Other common ones
    'secure-properties:config': ['key'], # The key for secure properties itself!
    'tls:context': ['keyStorePassword', 'trustStorePassword', 'privateKeyPassword'],
    'tls:key-store': ['password', 'keyPassword'], # Direct attributes on key-store
    # Generic catch-all for elements that might be used for credentials
    # This is broad, use with caution or make more specific if possible
    'anypoint-mq:config': ['clientId', 'clientSecret'],
    'amqp:config': ['password', 'saslPassword'],
    'objectstore:config': ['spring:property_os_encryption_key', 'value'], # if spring bean used for encryption key
    # Add more based on common connectors and their typical configuration elements/attributes
}


# Define Module-Level Constants (Original)
MULE_NAMESPACES = {
    'http': 'http://www.mulesoft.org/schema/mule/http',
    'dw': 'http://www.mulesoft.org/schema/mule/ee/dw',
    'mule': 'http://www.mulesoft.org/schema/mule/core',
    'ee': 'http://www.mulesoft.org/schema/mule/ee/core', # Common for Try, Scatter-Gather etc.
    'scheduler': 'http://www.mulesoft.org/schema/mule/schedulers',
    'sftp': 'http://www.mulesoft.org/schema/mule/sftp',
    'ftp': 'http://www.mulesoft.org/schema/mule/ftp',
    'email': 'http://www.mulesoft.org/schema/mule/email',
    'jms': 'http://www.mulesoft.org/schema/mule/jms',
    'db': 'http://www.mulesoft.org/schema/mule/db',
    'salesforce': 'http://www.mulesoft.org/schema/mule/salesforce',
    'secure-properties': 'http://www.mulesoft.org/schema/mule/secure-properties',
    'tls': 'http://www.mulesoft.org/schema/mule/tls',
    'apikit': 'http://www.mulesoft.org/schema/mule/apikit',
    'vm': 'http://www.mulesoft.org/schema/mule/vm',
    'anypoint-mq': 'http://www.mulesoft.org/schema/mule/anypoint-mq',
    'amqp': 'http://www.mulesoft.org/schema/mule/amqp',
    'objectstore': 'http://www.mulesoft.org/schema/mule/objectstore',
    # Custom/older namespaces from original list; keep if projects might use them
    'concur': 'http://www.mulesoft.org/schema/mule/concur',
    'smb': 'http://www.mulesoft.org/schema/mule/smb',
    's3': 'http://www.mulesoft.org/schema/mule/s3', # Assuming this is a custom or older namespace
    'spring': 'http://www.springframework.org/schema/beans', # For spring beans
}
CAMEL_CASE_REGEX = r'^[a-z][a-zA-Z0-9]*$'
FLOW_NAME_VALID_CHAR_REGEX = r'^[a-zA-Z0-9_.-]+$' # Allow underscores, dots, hyphens in flow names
DEFAULT_SCAN_PATH_NAME = "src/main/mule"
EXCLUDED_DIRS = ('target', 'test', '.mule', '.vscode', 'exchange_modules') # Added more common exclusions
EXCLUDED_FILE_SUBSTRINGS = ('munit', '.example.') # Added .example.
POM_XML_FILE_NAME = 'pom.xml'


def get_element_xml_path(element):
    """
    Generates a simplified XPath-like string for an lxml element.
    e.g., flow[name=myFlow]/logger
    """
    path_parts = []
    current = element
    while current is not None and current.getparent() is not None: # Stop before root document
        tag_name = etree.QName(current.tag).localname
        name_attr = current.get('name')
        if name_attr:
            path_parts.append(f"{tag_name}[name={name_attr}]")
        else:
            # Try to get 'doc:name' if 'name' is not present for better identification
            doc_name_attr = current.get('{http://www.mulesoft.org/schema/mule/documentation}name')
            if doc_name_attr:
                 path_parts.append(f"{tag_name}[doc:name={doc_name_attr}]")
            else:
                path_parts.append(tag_name)
        current = current.getparent()
    return "/".join(reversed(path_parts)) if path_parts else etree.QName(element.tag).localname


def get_element_identifier_for_sens_check(element):
    """
    Creates an identifier for an element to be used as a key in SENSITIVE_MULE_ATTRIBUTES.
    Format: 'prefix:localname' or just 'localname' if no standard prefix is obvious.
    """
    qname = etree.QName(element.tag)
    localname = qname.localname.lower()
    
    # Try to find a known prefix from MULE_NAMESPACES
    ns_uri = qname.namespace
    if ns_uri:
        for prefix, uri in MULE_NAMESPACES.items():
            if uri == ns_uri:
                return f"{prefix}:{localname}"
    
    # Fallback to just localname if no known prefix or no namespace
    # This makes the SENSITIVE_MULE_ATTRIBUTES map more flexible but requires careful definition.
    return localname


def check_hardcoded_secrets_in_mule_xml(root, file_path):
    issues = []
    if root is None:
        return issues

    for element in root.iter('*'): # Iterate over all elements
        elem_tag_local = etree.QName(element.tag).localname.lower()
        element_path = get_element_xml_path(element)
        value_excerpt_len = 50

        # 1. Check element tag name (less common for secrets, but possible for misconfigurations)
        if element.text and isinstance(element.text, str) and element.text.strip():
            if elem_tag_local in LOWERCASE_PASSWORD_KEYWORDS:
                issues.append({
                    'file_path': file_path, 'xml_path': element_path, 'element_tag': element.tag,
                    'attribute_name': None, 'value_excerpt': element.text.strip()[:value_excerpt_len] + ('...' if len(element.text.strip()) > value_excerpt_len else ''),
                    'issue_type': 'HardcodedSecretXML',
                    'message': f"Element tag <{elem_tag_local}> matches a password keyword and contains text."
                })
            elif elem_tag_local in LOWERCASE_GENERIC_SECRET_KEYWORDS:
                issues.append({
                    'file_path': file_path, 'xml_path': element_path, 'element_tag': element.tag,
                    'attribute_name': None, 'value_excerpt': element.text.strip()[:value_excerpt_len] + ('...' if len(element.text.strip()) > value_excerpt_len else ''),
                    'issue_type': 'HardcodedSecretXML',
                    'message': f"Element tag <{elem_tag_local}> matches a generic secret keyword and contains text."
                })

        # 2. Check element text content for secret patterns
        if element.text and isinstance(element.text, str):
            text_value = element.text.strip()
            if text_value: # Ensure not just whitespace
                for pattern_obj in COMPILED_COMMON_PASSWORD_PATTERNS:
                    if pattern_obj.search(text_value):
                        issues.append({
                            'file_path': file_path, 'xml_path': element_path, 'element_tag': element.tag,
                            'attribute_name': None, 'value_excerpt': text_value[:value_excerpt_len] + ('...' if len(text_value) > value_excerpt_len else ''),
                            'issue_type': 'SuspiciousValueXML',
                            'message': f"Text content of <{elem_tag_local}> matches common password pattern: {pattern_obj.pattern}"
                        })
                for pattern_obj in COMPILED_GENERIC_SECRET_VALUE_PATTERNS:
                    if pattern_obj.search(text_value):
                        issues.append({
                            'file_path': file_path, 'xml_path': element_path, 'element_tag': element.tag,
                            'attribute_name': None, 'value_excerpt': text_value[:value_excerpt_len] + ('...' if len(text_value) > value_excerpt_len else ''),
                            'issue_type': 'SuspiciousValueXML',
                            'message': f"Text content of <{elem_tag_local}> matches generic secret pattern: {pattern_obj.pattern}"
                        })
        
        # 3. Check attributes for keywords and patterns
        for attr_name, attr_value_raw in element.attrib.items():
            if not isinstance(attr_value_raw, str): # Ensure attribute value is a string
                continue 
            attr_value = attr_value_raw.strip()
            if not attr_value: # Skip empty or whitespace-only attributes
                continue

            attr_name_lower = attr_name.lower()
            
            # Check attribute name keywords
            if attr_name_lower in LOWERCASE_PASSWORD_KEYWORDS:
                issues.append({
                    'file_path': file_path, 'xml_path': element_path, 'element_tag': element.tag,
                    'attribute_name': attr_name, 'value_excerpt': attr_value[:value_excerpt_len] + ('...' if len(attr_value) > value_excerpt_len else ''),
                    'issue_type': 'HardcodedSecretXML',
                    'message': f"Attribute '{attr_name}' in <{elem_tag_local}> matches a password keyword."
                })
            elif attr_name_lower in LOWERCASE_GENERIC_SECRET_KEYWORDS:
                issues.append({
                    'file_path': file_path, 'xml_path': element_path, 'element_tag': element.tag,
                    'attribute_name': attr_name, 'value_excerpt': attr_value[:value_excerpt_len] + ('...' if len(attr_value) > value_excerpt_len else ''),
                    'issue_type': 'HardcodedSecretXML',
                    'message': f"Attribute '{attr_name}' in <{elem_tag_local}> matches a generic secret keyword."
                })

            # Check attribute value patterns (only if not already caught by keyword on name)
            # This avoids double-reporting if e.g. an attribute "password" has value "password"
            already_reported_by_name = any(
                issue['attribute_name'] == attr_name and issue['element_tag'] == element.tag for issue in issues
            )
            if not already_reported_by_name:
                for pattern_obj in COMPILED_COMMON_PASSWORD_PATTERNS:
                    if pattern_obj.search(attr_value):
                        issues.append({
                            'file_path': file_path, 'xml_path': element_path, 'element_tag': element.tag,
                            'attribute_name': attr_name, 'value_excerpt': attr_value[:value_excerpt_len] + ('...' if len(attr_value) > value_excerpt_len else ''),
                            'issue_type': 'SuspiciousValueXML',
                            'message': f"Value of attribute '{attr_name}' in <{elem_tag_local}> matches common password pattern: {pattern_obj.pattern}"
                        })
                for pattern_obj in COMPILED_GENERIC_SECRET_VALUE_PATTERNS:
                    if pattern_obj.search(attr_value):
                        issues.append({
                            'file_path': file_path, 'xml_path': element_path, 'element_tag': element.tag,
                            'attribute_name': attr_name, 'value_excerpt': attr_value[:value_excerpt_len] + ('...' if len(attr_value) > value_excerpt_len else ''),
                            'issue_type': 'SuspiciousValueXML',
                            'message': f"Value of attribute '{attr_name}' in <{elem_tag_local}> matches generic secret pattern: {pattern_obj.pattern}"
                        })
    return issues


def check_secure_properties_usage_in_mule_xml(root, file_path):
    issues = []
    if root is None:
        return issues

    for element in root.iter('*'): # Iterate over all elements
        # Use a helper to create a consistent identifier for SENSITIVE_MULE_ATTRIBUTES keys
        element_identifier = get_element_identifier_for_sens_check(element)
        element_path = get_element_xml_path(element)
        
        sensitive_attributes_for_element = SENSITIVE_MULE_ATTRIBUTES.get(element_identifier, [])
        
        # Also check for generic sensitive attribute names on *any* element if not specifically typed
        # For example, if a 'password' attribute appears on an unlisted element type.
        # This requires SENSITIVE_MULE_ATTRIBUTES to have a generic key like '*' or None,
        # or we can iterate through a separate list of universally sensitive attr names.
        # For now, let's stick to the defined element types in SENSITIVE_MULE_ATTRIBUTES.
        
        if not sensitive_attributes_for_element:
            continue

        for attr_name_to_check in sensitive_attributes_for_element:
            attr_value_raw = element.get(attr_name_to_check) # Direct attribute name check

            if attr_value_raw is not None and isinstance(attr_value_raw, str):
                attr_value = attr_value_raw.strip()
                if attr_value: # If attribute has a non-empty value
                    is_secure_placeholder = False
                    for secure_pattern in SECURE_PROPERTY_PATTERNS:
                        if secure_pattern.fullmatch(attr_value): # Use fullmatch for property placeholders
                            is_secure_placeholder = True
                            break
                    
                    if not is_secure_placeholder:
                        # It's either plain text or an insecure property placeholder
                        issues.append({
                            'file_path': file_path,
                            'xml_path': element_path,
                            'element_tag': element.tag,
                            'attribute_name': attr_name_to_check,
                            'value_excerpt': attr_value[:50] + ('...' if len(attr_value) > 50 else ''),
                            'issue_type': 'InsecurePropertyUseXML',
                            'message': f"Attribute '{attr_name_to_check}' on element <{etree.QName(element.tag).localname}> "
                                       f"should use a secure property (e.g., ${{secure::...}}) but found: '{attr_value[:30]}...'."
                        })
    return issues


def is_camel_case(name):
    """
    Checks if a given name is in camel case format using CAMEL_CASE_REGEX.

    :param name: The name string to check.
    :return: True if the name is in camel case format, otherwise False.
    """
    return re.match(CAMEL_CASE_REGEX, name) is not None

def check_flow_names(root):
    """
    Checks for issues with flow names in the XML configuration.
    - Flow names should comply with camel case format.
    - Flow names should contain only alphanumeric characters and underscores, dots, hyphens.

    :param root: The root element of the parsed XML.
    :return: A list of issue description strings.
    """
    issues = []
    # Find all elements that can have a 'name' attribute and represent a flow-like structure
    # This includes mule:flow, mule:sub-flow, mule:flow-ref (though flow-ref 'name' refers to another flow)
    # For this check, we are primarily interested in definitions: flow and sub-flow.
    for flow_element in root.xpath("//mule:flow[@name] | //mule:sub-flow[@name]", namespaces=MULE_NAMESPACES):
        name = flow_element.get("name")
        element_type = etree.QName(flow_element.tag).localname # "flow" or "sub-flow"
        
        if not name: # Should not happen with [@name] XPath, but good practice
            issues.append(f"{element_type.capitalize()} is missing a name attribute. ({get_element_xml_path(flow_element)})")
            continue

        if not is_camel_case(name):
            issues.append(f"{element_type.capitalize()} name '{name}' does not comply with camel case format. ({get_element_xml_path(flow_element)})")
        
        if not re.fullmatch(FLOW_NAME_VALID_CHAR_REGEX, name): # Use fullmatch
            issues.append(f"{element_type.capitalize()} name '{name}' contains invalid characters. Allowed: alphanumeric, underscore, dot, hyphen. ({get_element_xml_path(flow_element)})")
    return issues

def check_http_listener(root):
    """
    Checks for issues with HTTP Listener configurations.
    - HTTP Listeners should have a defined path attribute.

    :param root: The root element of the parsed XML.
    :return: A list of issue description strings.
    """
    issues = []
    for listener in root.findall(".//http:listener", namespaces=MULE_NAMESPACES):
        path = listener.get("path")
        if not path:
            issues.append("HTTP Listener is missing a path attribute.")
    return issues

def check_logger(root):
    """
    Checks for issues with Logger configurations.
    - Loggers should have a defined message attribute.

    :param root: The root element of the parsed XML.
    :return: A list of issue description strings.
    """
    issues = []
    for logger_elem in root.findall(".//mule:logger", namespaces=MULE_NAMESPACES): # Renamed variable to avoid conflict
        message = logger_elem.get("message")
        if not message:
            issues.append("Logger is missing a message attribute.")
    return issues

def check_dataweave(root):
    """
    Checks for issues with DataWeave transformations.
    - DataWeave transformations should include a dw:set-payload or dw:set-variable, etc.
    This check is simplified to ensure there's *some* output definition.

    :param root: The root element of the parsed XML.
    :return: A list of issue description strings.
    """
    issues = []
    for transform in root.findall(".//dw:transform-message", namespaces=MULE_NAMESPACES):
        # Check for common DataWeave output elements
        if not transform.xpath("./dw:set-payload | ./dw:set-variable | ./dw:set-session-variable | ./dw:set-property", namespaces=MULE_NAMESPACES):
            issues.append(f"DataWeave transform-message is missing an output directive (e.g., dw:set-payload, dw:set-variable). ({get_element_xml_path(transform)})")
    return issues

def check_http_response(root):
    """
    Checks for issues with HTTP Response Builders.
    - HTTP Response Builders should have a defined status-code element.

    :param root: The root element of the parsed XML.
    :return: A list of issue description strings.
    """
    issues = []
    # This check might be too specific, as response can be set in many ways.
    # Consider if http:response-builder is the only target or if it's about ensuring a response is built.
    for response in root.findall(".//http:response-builder", namespaces=MULE_NAMESPACES):
        status_code = response.find(".//http:status-code", namespaces=MULE_NAMESPACES)
        if status_code is None:
            issues.append("HTTP Response Builder is missing a status-code element.")
    return issues

def check_scheduler(root):
    """
    Checks for issues with Scheduler configurations.
    - Schedulers should have a defined frequency attribute.
    Note: This checks for scheduler:inbound-endpoint which is older.
    Modern schedulers are <scheduler:scheduler> with <scheduling-strategy>.

    :param root: The root element of the parsed XML.
    :return: A list of issue description strings.
    """
    issues = []
    # Check for modern scheduler
    for scheduler_modern in root.findall(".//scheduler:scheduler", namespaces=MULE_NAMESPACES):
        strategy = scheduler_modern.find("./scheduler:scheduling-strategy/*[1]", namespaces=MULE_NAMESPACES)
        if strategy is not None:
            if strategy.tag == f"{{{MULE_NAMESPACES['scheduler']}}}fixed-frequency":
                if not strategy.get("frequency"):
                    issues.append("Scheduler (modern) with fixed-frequency is missing a frequency attribute.")
            elif strategy.tag == f"{{{MULE_NAMESPACES['scheduler']}}}cron":
                 if not strategy.get("expression"):
                    issues.append("Scheduler (modern) with cron strategy is missing an expression attribute.")
        else:
            issues.append("Scheduler (modern) is missing a scheduling strategy (e.g., fixed-frequency or cron).")

    # Check for older scheduler:inbound-endpoint if still relevant
    for scheduler_old in root.findall(".//scheduler:inbound-endpoint", namespaces=MULE_NAMESPACES): # Old syntax
        frequency = scheduler_old.get("frequency")
        if not frequency:
            issues.append("Scheduler (legacy inbound-endpoint) is missing a frequency attribute.")
    return issues


def check_concur(root): # Assuming 'concur' is a placeholder for a real connector
    """
    Checks for issues with Concur connector configurations (example).
    - Concur connectors should have a defined config-ref attribute.

    :param root: The root element of the parsed XML.
    :return: A list of issue description strings.
    """
    issues = []
    # Replace 'concur:connector' with actual element names if this is a real check
    if 'concur' in MULE_NAMESPACES: # Check if namespace is actually defined
        for concur_elem in root.findall(".//concur:connector", namespaces=MULE_NAMESPACES):
            config_ref = concur_elem.get("config-ref")
            if not config_ref:
                issues.append("Concur connector is missing a config-ref attribute.")
    return issues

def check_http_requester(root):
    """
    Checks for issues with HTTP Requester configurations.
    - HTTP Requesters should have a defined URL attribute (or url attribute within request-connection).

    :param root: The root element of the parsed XML.
    :return: A list of issue description strings.
    """
    issues = []
    for requester in root.findall(".//http:request", namespaces=MULE_NAMESPACES): # http:request is more common
        # URL can be on the requester or within its connection element
        url_attr = requester.get("url")
        connection_element = requester.find("./http:request-connection", namespaces=MULE_NAMESPACES)
        url_in_connection = False
        if connection_element is not None:
            url_in_connection = connection_element.get("url") is not None
        
        if not url_attr and not url_in_connection:
            issues.append("HTTP Requester is missing a URL attribute (either directly or in its connection).")
    return issues

def check_ftp(root):
    """
    Checks for issues with FTP configurations (e.g., ftp:listener or ftp:outbound-endpoint).
    - FTP components should have defined host and port attributes, typically via config-ref.
    This check is simplified and might need to be more specific to listener/requester and config.

    :param root: The root element of the parsed XML.
    :return: A list of issue description strings.
    """
    issues = []
    # Example for ftp:listener - adapt for other FTP operations
    for ftp_listener in root.findall(".//ftp:listener", namespaces=MULE_NAMESPACES):
        config_ref = ftp_listener.get("config-ref")
        if not config_ref:
            issues.append("FTP Listener is missing a config-ref attribute.")
        # Further checks could involve looking up the config_ref and validating its host/port.
    return issues

def check_sftp(root):
    """
    Checks for issues with SFTP configurations (e.g., sftp:listener or sftp:outbound-endpoint).
    - SFTP components should have defined host and port attributes, typically via config-ref.
    This check is simplified.

    :param root: The root element of the parsed XML.
    :return: A list of issue description strings.
    """
    issues = []
    for sftp_op in root.findall(".//sftp:listener", namespaces=MULE_NAMESPACES) + \
                   root.findall(".//sftp:outbound-endpoint", namespaces=MULE_NAMESPACES) + \
                   root.findall(".//sftp:on-new-or-updated-file", namespaces=MULE_NAMESPACES): # Common SFTP ops
        config_ref = sftp_op.get("config-ref")
        if not config_ref:
            issues.append(f"SFTP component '{sftp_op.tag.split('}')[-1]}' is missing a config-ref attribute.")
    return issues

def check_smb(root): # Assuming 'smb' is for a specific SMB connector
    """
    Checks for issues with SMB configurations (example).
    - SMB components should have defined host, port, and username attributes (likely via config-ref).

    :param root: The root element of the parsed XML.
    :return: A list of issue description strings.
    """
    issues = []
    if 'smb' in MULE_NAMESPACES: # Check if namespace is actually defined
        for smb_op in root.findall(".//smb:*" , namespaces=MULE_NAMESPACES): # Generic check for any smb op
            config_ref = smb_op.get("config-ref")
            if not config_ref:
                 issues.append(f"SMB component '{smb_op.tag.split('}')[-1]}' is missing a config-ref attribute.")
    return issues


def check_vm(root):
    """
    Checks for issues with VM configurations (e.g., vm:listener, vm:publish).
    - VM components should have a defined queueName attribute.
    - Max retries is often on the queue config, not directly on listener/publish.

    :param root: The root element of the parsed XML.
    :return: A list of issue description strings.
    """
    issues = []
    for vm_op in root.findall(".//vm:listener", namespaces=MULE_NAMESPACES) + \
                 root.findall(".//vm:publish", namespaces=MULE_NAMESPACES):
        queue_name = vm_op.get("queueName") # Note: queueName with capital N
        if not queue_name:
            issues.append(f"VM component '{vm_op.tag.split('}')[-1]}' is missing a queueName attribute.")
        # maxRetries is usually part of vm:config and vm:queue definition, not on each operation.
    return issues

def check_s3(root): # Assuming 's3' is for AWS S3 connector
    """
    Checks for issues with S3 Bucket configurations (example).
    - S3 components should typically have a config-ref. Bucket name might be on the operation.

    :param root: The root element of the parsed XML.
    :return: A list of issue description strings.
    """
    issues = []
    if 's3' in MULE_NAMESPACES: # Check if namespace is actually defined
         # Example for a generic s3 operation, replace with actual S3 component names
        for s3_op in root.findall(".//*[starts-with(name(), 's3:')]", namespaces=MULE_NAMESPACES):
            # Most S3 operations require a bucketName attribute directly or via config.
            # A config-ref is also very common for S3 connectors.
            config_ref = s3_op.get("config-ref")
            bucket_name = s3_op.get("bucketName")
            if not config_ref and not bucket_name: # Simplified: needs one or the other (or config has bucket)
                 issues.append(f"S3 component '{s3_op.tag.split('}')[-1]}' is missing a bucketName or config-ref attribute.")
    return issues

def check_smtp(root):
    """
    Checks for issues with SMTP configurations (e.g., smtp:send).
    - SMTP components should have defined host, port, and username, typically via config-ref.

    :param root: The root element of the parsed XML.
    :return: A list of issue description strings.
    """
    issues = []
    for smtp_send in root.findall(".//smtp:send", namespaces=MULE_NAMESPACES):
        config_ref = smtp_send.get("config-ref")
        if not config_ref:
            issues.append("SMTP send operation is missing a config-ref attribute.")
    return issues


def review_mulesoft_code(file_path):
    """
    Reviews a MuleSoft XML configuration file for common issues, including hardcoded secrets
    and insecure property usage. Reads the XML file, parses it, and performs various checks.

    :param file_path: The path to the XML file to review.
    :return: A list of dictionaries. Each dictionary represents an issue found
             (keys: 'file_path', 'type', 'message', 'xml_path', etc.) or an error encountered
             during processing. Returns an empty list if no issues are found
             and no errors occur.
    """
    logger.debug(f"Attempting to review MuleSoft code in file: {file_path}")
    issues_found = []
    try:
        # Use a parser that removes comments and processing instructions, can help with large files
        parser = etree.XMLParser(remove_comments=True, remove_pis=True, resolve_entities=False)
        with open(file_path, 'rb') as file: # Read as bytes for lxml
            xml_bytes = file.read()
        
        if not xml_bytes.strip(): # Check if file is effectively empty (e.g. only whitespace)
            logger.warning(f"File is empty or contains only whitespace: {file_path}")
            return [{'file_path': file_path, 'type': 'FileReadError', 'message': 'File is empty or contains only whitespace.'}]

        root = etree.fromstring(xml_bytes, parser=parser)
        
        # Standard code review checks
        standard_check_functions = [
            check_flow_names, check_http_listener, check_logger, check_dataweave,
            check_http_response, check_scheduler, check_concur, check_http_requester,
            check_ftp, check_sftp, check_smb, check_vm, check_s3, check_smtp
        ]

        for check_func in standard_check_functions:
            try:
                results = check_func(root) # These original checks return list of strings
                for issue_message in results:
                    # Attempt to find the element related to the issue for path, less precise
                    # This part is a simplification; ideally, each check_func would return structured data with element info
                    issues_found.append({
                        'file_path': file_path,
                        'xml_path': 'N/A (Standard Check)', # Path might not be easily available from old checks
                        'element_tag': 'N/A',
                        'type': 'CodeReviewIssue', # Generic type for original checks
                        'message': f"{check_func.__name__.replace('check_', '').capitalize()}: {issue_message}"
                    })
            except Exception as e:
                logger.error(f"Error during {check_func.__name__} for file {file_path}: {e}", exc_info=True)
                issues_found.append({
                    'file_path': file_path,
                    'xml_path': 'N/A',
                    'element_tag': 'N/A',
                    'type': 'CheckFunctionError',
                    'message': f"Error in {check_func.__name__}: {e}"
                })
        
        # Security specific checks
        security_issues = check_hardcoded_secrets_in_mule_xml(root, file_path)
        issues_found.extend(security_issues)
        
        secure_prop_issues = check_secure_properties_usage_in_mule_xml(root, file_path)
        issues_found.extend(secure_prop_issues)


        if not issues_found: # Only log if no issues of *any* type were found
            logger.debug(f"No code review or security issues found in {file_path}")
        
        return issues_found

    except (IOError, OSError) as e:
        logger.error(f"File read error for {file_path}: {e}", exc_info=True)
        return [{'file_path': file_path, 'type': 'FileReadError', 'message': str(e)}]
    except etree.XMLSyntaxError as e:
        logger.error(f"XML syntax error in file {file_path}: {e}", exc_info=True)
        # Provide more context for XMLSyntaxError if possible
        error_message = f"XMLSyntaxError: {e.msg} at line {e.lineno}, column {e.offset}"
        return [{'file_path': file_path, 'type': 'XMLSyntaxError', 'message': error_message}]
    except Exception as e: # Catch-all for other unexpected errors during parsing or processing
        logger.error(f"Unexpected error processing file {file_path}: {e}", exc_info=True)
        return [{'file_path': file_path, 'type': 'GenericProcessingError', 'message': str(e)}]


def review_all_files(package_folder_path):
    """
    Recursively reviews all relevant XML files in the MuleSoft package's
    `src/main/mule` directory, ignoring specified excluded directories and files.

    Calls `review_mulesoft_code` for each valid XML file and collects all
    reported issues or errors.

    :param package_folder_path: The root path of the MuleSoft package.
    :return: A flat list of dictionaries, where each dictionary represents an issue
             or an error encountered during processing for any of a file's checks.
             Returns an empty list if no issues are found or the scan path doesn't exist.
    """
    all_issues_and_errors = []
    scan_directory = os.path.join(package_folder_path, DEFAULT_SCAN_PATH_NAME)
    logger.info(f"Starting code review for XML files in: {scan_directory}")

    if not os.path.isdir(scan_directory):
        logger.error(f"Scan directory does not exist: {scan_directory}. Cannot perform code review.")
        return []

    for root_dir, dirs, files in os.walk(scan_directory):
        # Modify dirs in-place to skip excluded directories
        dirs[:] = [d for d in dirs if d not in EXCLUDED_DIRS]
        
        for file_name in files:
            if file_name == POM_XML_FILE_NAME:
                logger.debug(f"Skipping POM file: {os.path.join(root_dir, file_name)}")
                continue

            if not file_name.lower().endswith('.xml'):
                logger.debug(f"Skipping non-XML file: {os.path.join(root_dir, file_name)}")
                continue
                
            skip_file = False
            for substring in EXCLUDED_FILE_SUBSTRINGS:
                if substring in file_name.lower():
                    logger.debug(f"Skipping file due to excluded substring '{substring}': {os.path.join(root_dir, file_name)}")
                    skip_file = True
                    break
            if skip_file:
                continue

            file_path = os.path.join(root_dir, file_name)
            logger.info(f"Reviewing file: {file_path}")
            
            file_results = review_mulesoft_code(file_path)
            if file_results: # Can be empty list if no issues, or list of error dicts
                all_issues_and_errors.extend(file_results)
            else:
                logger.info(f"No issues or errors reported for: {file_path}")
                # Optionally, could add a "success" entry if needed for reporting
                # all_issues_and_errors.append({'file_path': file_path, 'type': 'NoIssuesFound', 'message': 'File reviewed, no issues.'})


    if not all_issues_and_errors:
        logger.info(f"Code review completed. No issues or errors found in {scan_directory}.")
    else:
        logger.info(f"Code review completed. Found {len(all_issues_and_errors)} total issues/errors in {scan_directory}.")
        
    return all_issues_and_errors

# Example usage (can be removed or kept for testing)
# if __name__ == '__main__':
#     logging.basicConfig(level=logging.DEBUG) # Configure logging for testing
#     # Define the MuleSoft package folder path here
#     package_path = 'path_to_your_mulesoft_project' # Replace
#     validation_output = review_all_files(package_path)
#     if validation_output:
#         for item in validation_output:
#             logger.debug(item) # Use logger for example output too
#     else:
#         logger.debug("No code review issues found or scan path invalid.")
