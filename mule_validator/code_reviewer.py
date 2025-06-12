"""
This module provides functions to review MuleSoft XML configuration files for common
issues, adherence to naming conventions, and checks for specific configurations
like the use of Mule Secure Properties.
"""
import os
from lxml import etree
import re
from mule_validator.flow_validator import validate_flow_name_camel_case
# tabulate is not used in this module directly anymore, but was part of the original file.
# If other parts of the project rely on it being imported here, it could be kept,
# otherwise, it's a candidate for removal from this specific file's imports.
# from tabulate import tabulate

def is_camel_case(name: str) -> bool:
    """
    Checks if a given name is in camel case format.

    A name is considered camel case if it starts with a lowercase letter,
    followed by any sequence of alphanumeric characters.

    Args:
        name (str): The name string to check.

    Returns:
        bool: True if the name is in camel case format, otherwise False.
    """
    return re.match(r'^[a-z][a-zA-Z0-9]*$', name) is not None

# Helper function to check for secure properties configuration
def _contains_secure_properties_config(root: etree._Element, namespaces: dict) -> bool:
    """
    Checks if the XML configuration contains a Mule Secure Properties <secure-properties:config> element.

    This indicates that the project is set up to use Mule's property encryption features.

    Args:
        root (lxml.etree._Element): The root element of the parsed XML.
        namespaces (dict): A dictionary of XML namespaces mapping prefixes to URIs.

    Returns:
        bool: True if a <secure-properties:config> element is found, otherwise False.
    """
    return root.find(".//secure-properties:config", namespaces=namespaces) is not None

def check_flow_names(root, namespaces):
    """
    Checks for issues with flow names in the XML configuration.

    Flow names are validated for camel case format. The validation logic specifically
    targets the core part of the flow name, attempting to exclude potential APIkit
    router or other namespace prefixes/suffixes before applying camel case rules.

    Args:
        root (lxml.etree._Element): The root element of the parsed XML.
        namespaces (dict): A dictionary of XML namespaces used in the MuleSoft configuration.

    Returns:
        list[str]: A list of issue description strings found related to flow names.
    """
    issues = []
    for flow in root.findall(".//mule:flow", namespaces=namespaces):
        name = flow.get("name")
        if not name:
            issues.append("Flow is missing a name attribute.")
        else:
            name_to_check = name
            first_colon_idx = name.find(':')
            if first_colon_idx != -1:
                # Part after the first colon
                substring_after_first_colon = name[first_colon_idx+1:]
                second_colon_idx = substring_after_first_colon.find(':')
                if second_colon_idx != -1:
                    # There is a second colon, take the part between the first and second
                    name_to_check = substring_after_first_colon[:second_colon_idx]
                else:
                    # No second colon, take the whole part after the first colon
                    name_to_check = substring_after_first_colon

            # It's possible name_to_check is empty if the format is like "get::config" or "http:"
            # Add a check to ensure name_to_check is not empty before validation
            if not name_to_check:
                issues.append(f"Flow name '{name}' results in an empty part for validation after APIkit prefix/suffix removal.")
            elif not validate_flow_name_camel_case(name_to_check):
                issues.append(f"Flow name part '{name_to_check}' (from original: '{name}') does not comply with camel case format.")
    return issues

def check_http_listener(root: etree._Element, namespaces: dict) -> list[str]:
    """
    Checks for issues with HTTP Listener configurations.

    - HTTP Listeners should have a defined `path` attribute.

    Args:
        root (lxml.etree._Element): The root element of the parsed XML.
        namespaces (dict): A dictionary of XML namespaces.

    Returns:
        list[str]: A list of issue description strings.
    """
    issues = []
    for listener in root.findall(".//http:listener", namespaces=namespaces):
        path = listener.get("path")
        if not path:
            issues.append("HTTP Listener is missing a path attribute.")
    return issues

def check_logger(root, namespaces):
    """
    Checks for issues with Logger configurations.

    - Loggers should have a defined `message` attribute.

    Args:
        root (lxml.etree._Element): The root element of the parsed XML.
        namespaces (dict): A dictionary of XML namespaces.

    Returns:
        list[str]: A list of issue description strings.
    """
    issues = []
    for logger in root.findall(".//mule:logger", namespaces=namespaces):
        message = logger.get("message")
        if not message:
            issues.append("Logger is missing a message attribute.")
    return issues

def check_dataweave(root, namespaces):
    """
    Checks for issues with DataWeave transformations.

    - DataWeave transformations (`dw:transform-message`) should include a `dw:set-payload` child element.

    Args:
        root (lxml.etree._Element): The root element of the parsed XML.
        namespaces (dict): A dictionary of XML namespaces.

    Returns:
        list[str]: A list of issue description strings.
    """
    issues = []
    for transform in root.findall(".//dw:transform-message", namespaces=namespaces):
        set_payload = transform.find(".//dw:set-payload", namespaces=namespaces)
        if set_payload is None:
            issues.append("DataWeave transformation is missing a set-payload element.")
    return issues

def check_http_response(root, namespaces):
    """
    Checks for issues with HTTP Response Builders (`http:response-builder`).

    - HTTP Response Builders should have a defined `http:status-code` child element.

    Args:
        root (lxml.etree._Element): The root element of the parsed XML.
        namespaces (dict): A dictionary of XML namespaces.

    Returns:
        list[str]: A list of issue description strings.
    """
    issues = []
    for response in root.findall(".//http:response-builder", namespaces=namespaces):
        status_code = response.find(".//http:status-code", namespaces=namespaces)
        if status_code is None:
            issues.append("HTTP Response Builder is missing a status-code element.")
    return issues

def check_scheduler(root, namespaces):
    """
    Checks for issues with Scheduler configurations (`scheduler:inbound-endpoint`).

    - Schedulers should have a defined `frequency` attribute.

    Args:
        root (lxml.etree._Element): The root element of the parsed XML.
        namespaces (dict): A dictionary of XML namespaces.

    Returns:
        list[str]: A list of issue description strings.
    """
    issues = []
    for scheduler in root.findall(".//scheduler:inbound-endpoint", namespaces=namespaces):
        frequency = scheduler.get("frequency")
        if not frequency:
            issues.append("Scheduler is missing a frequency attribute.")
    return issues

def check_concur(root, namespaces):
    """
    Checks for issues with Concur connector configurations (`concur:connector`).

    - Concur connectors should have a defined `config-ref` attribute.

    Args:
        root (lxml.etree._Element): The root element of the parsed XML.
        namespaces (dict): A dictionary of XML namespaces.

    Returns:
        list[str]: A list of issue description strings.
    """
    issues = []
    for concur in root.findall(".//concur:connector", namespaces=namespaces):
        config_ref = concur.get("config-ref")
        if not config_ref:
            issues.append("Concur connector is missing a config-ref attribute.")
    return issues

def check_http_requester(root, namespaces):
    """
    Checks for issues with HTTP Requester configurations (`http:requester`).

    - HTTP Requesters should have a defined `url` attribute.

    Args:
        root (lxml.etree._Element): The root element of the parsed XML.
        namespaces (dict): A dictionary of XML namespaces.

    Returns:
        list[str]: A list of issue description strings.
    """
    issues = []
    for requester in root.findall(".//http:requester", namespaces=namespaces):
        url = requester.get("url")
        if not url:
            issues.append("HTTP Requester is missing a URL attribute.")
    return issues

def check_ftp(root, namespaces):
    """
    Checks for issues with FTP Inbound Endpoint configurations (`ftp:inbound-endpoint`).

    - FTP Inbound Endpoints should have defined `host` and `port` attributes.

    Args:
        root (lxml.etree._Element): The root element of the parsed XML.
        namespaces (dict): A dictionary of XML namespaces.

    Returns:
        list[str]: A list of issue description strings.
    """
    issues = []
    for ftp in root.findall(".//ftp:inbound-endpoint", namespaces=namespaces):
        host = ftp.get("host")
        if not host:
            issues.append("FTP Inbound Endpoint is missing a host attribute.")
        port = ftp.get("port")
        if not port:
            issues.append("FTP Inbound Endpoint is missing a port attribute.")
    return issues

def check_sftp(root, namespaces):
    """
    Checks for issues with SFTP Inbound Endpoint configurations (`sftp:inbound-endpoint`).

    - SFTP Inbound Endpoints should have defined `host` and `port` attributes.

    Args:
        root (lxml.etree._Element): The root element of the parsed XML.
        namespaces (dict): A dictionary of XML namespaces.

    Returns:
        list[str]: A list of issue description strings.
    """
    issues = []
    for sftp in root.findall(".//sftp:inbound-endpoint", namespaces=namespaces):
        host = sftp.get("host")
        if not host:
            issues.append("SFTP Inbound Endpoint is missing a host attribute.")
        port = sftp.get("port")
        if not port:
            issues.append("SFTP Inbound Endpoint is missing a port attribute.")
    return issues

def check_smb(root, namespaces):
    """
    Checks for issues with SMB configurations (`smb:inbound-endpoint`).

    - SMB components should have defined `host`, `port`, and `username` attributes.

    Args:
        root (lxml.etree._Element): The root element of the parsed XML.
        namespaces (dict): A dictionary of XML namespaces.

    Returns:
        list[str]: A list of issue description strings.
    """
    issues = []
    for smb in root.findall(".//smb:inbound-endpoint", namespaces=namespaces):
        host = smb.get("host")
        if not host:
            issues.append("SMB Inbound Endpoint is missing a host attribute.")
        port = smb.get("port")
        if not port:
            issues.append("SMB Inbound Endpoint is missing a port attribute.")
        username = smb.get("username")
        if not username:
            issues.append("SMB Inbound Endpoint is missing a username attribute.")
    return issues

def check_vm(root, namespaces):
    """
    Checks for issues with VM configurations (`vm:inbound-endpoint`).

    - VM components should have defined `queue-name` and `max-retries` attributes.

    Args:
        root (lxml.etree._Element): The root element of the parsed XML.
        namespaces (dict): A dictionary of XML namespaces.

    Returns:
        list[str]: A list of issue description strings.
    """
    issues = []
    for vm in root.findall(".//vm:inbound-endpoint", namespaces=namespaces):
        queue_name = vm.get("queue-name")
        if not queue_name:
            issues.append("VM Inbound Endpoint is missing a queue-name attribute.")
        max_retries = vm.get("max-retries")
        if not max_retries:
            issues.append("VM Inbound Endpoint is missing a max-retries attribute.")
    return issues

def check_s3(root, namespaces):
    """
    Checks for issues with S3 Bucket configurations (`s3:inbound-endpoint`).

    - S3 Buckets should have defined `bucket-name` and `access-key` attributes.

    Args:
        root (lxml.etree._Element): The root element of the parsed XML.
        namespaces (dict): A dictionary of XML namespaces.

    Returns:
        list[str]: A list of issue description strings.
    """
    issues = []
    for s3 in root.findall(".//s3:inbound-endpoint", namespaces=namespaces):
        bucket_name = s3.get("bucket-name")
        if not bucket_name:
            issues.append("S3 Inbound Endpoint is missing a bucket-name attribute.")
        access_key = s3.get("access-key")
        if not access_key:
            issues.append("S3 Inbound Endpoint is missing an access-key attribute.")
    return issues

def check_smtp(root, namespaces):
    """
    Checks for issues with SMTP configurations (`smtp:outbound-endpoint`).

    - SMTP components should have defined `host`, `port`, and `username` attributes.

    Args:
        root (lxml.etree._Element): The root element of the parsed XML.
        namespaces (dict): A dictionary of XML namespaces.

    Returns:
        list[str]: A list of issue description strings.
    """
    issues = []
    for smtp in root.findall(".//smtp:outbound-endpoint", namespaces=namespaces):
        host = smtp.get("host")
        if not host:
            issues.append("SMTP Outbound Endpoint is missing a host attribute.")
        port = smtp.get("port")
        if not port:
            issues.append("SMTP Outbound Endpoint is missing a port attribute.")
        username = smtp.get("username")
        if not username:
            issues.append("SMTP Outbound Endpoint is missing a username attribute.")
    return issues

def review_mulesoft_code(file_path):
    """
    Reviews a single MuleSoft XML configuration file for common issues and checks
    if Mule Secure Properties configuration is present.

    Reads the XML file, parses it, and performs various checks (e.g., flow names,
    component configurations). Also detects the presence of a
    `<secure-properties:config>` element.

    Args:
        file_path (str): The path to the XML file to review.

    Returns:
        tuple[list[str], bool]: A tuple containing:
            - A list of issue description strings found in the XML file.
            - A boolean indicating True if a `<secure-properties:config>`
              element is found in this file, otherwise False.
    """
    try:
        # Read XML content from the file
        with open(file_path, 'r', encoding='utf-8') as file:
            xml_content = file.read()

        # Convert XML content to bytes
        xml_bytes = xml_content.encode('utf-8')

        # Parse XML content
        root = etree.fromstring(xml_bytes)
        
        # Define namespaces used in the MuleSoft configuration
        namespaces = {
            'http': 'http://www.mulesoft.org/schema/mule/core',
            'dw': 'http://www.mulesoft.org/schema/mule/ee/dw',
            'mule': 'http://www.mulesoft.org/schema/mule/core',
            'scheduler': 'http://www.mulesoft.org/schema/mule/scheduler',
            'concur': 'http://www.mulesoft.org/schema/mule/concur',
            'ftp': 'http://www.mulesoft.org/schema/mule/ftp',
            'sftp': 'http://www.mulesoft.org/schema/mule/sftp',
            'smb': 'http://www.mulesoft.org/schema/mule/smb',
            'vm': 'http://www.mulesoft.org/schema/mule/vm',
            's3': 'http://www.mulesoft.org/schema/mule/s3',
            'smtp': 'http://www.mulesoft.org/schema/mule/smtp',
            'secure-properties': 'http://www.mulesoft.org/schema/mule/secure-properties'
        }

        # Perform checks
        issues = []
        issues.extend(check_flow_names(root, namespaces))
        issues.extend(check_http_listener(root, namespaces))
        issues.extend(check_logger(root, namespaces))
        issues.extend(check_dataweave(root, namespaces))
        issues.extend(check_http_response(root, namespaces))
        issues.extend(check_scheduler(root, namespaces))
        issues.extend(check_concur(root, namespaces))
        issues.extend(check_http_requester(root, namespaces))
        issues.extend(check_ftp(root, namespaces))
        issues.extend(check_sftp(root, namespaces))
        issues.extend(check_smb(root, namespaces))
        issues.extend(check_vm(root, namespaces))
        issues.extend(check_s3(root, namespaces))
        # Removed duplicate check_s3 call
        issues.extend(check_smtp(root, namespaces))

        # Check for Mule Secure Properties configuration in this specific file
        uses_secure_config_in_file = _contains_secure_properties_config(root, namespaces)
        
        return issues, uses_secure_config_in_file
    except etree.XMLSyntaxError as e:
        # If XML syntax is invalid, we cannot parse it to check for secure properties.
        # Return the syntax error and False for secure properties usage in this file.
        return [f"XML Syntax Error in file {file_path}: {str(e)}"], False
    except Exception as e:
        # For any other error during file processing, return the error and False.
        return [f"Error processing file {file_path}: {str(e)}"], False

def review_all_files(directory):
    """
    Recursively reviews all MuleSoft XML configuration files in a given directory.

    It ignores files located in 'target', 'test', or 'munit' subfolders, and also
    skips 'pom.xml' files. For each eligible XML file, it calls `review_mulesoft_code`
    to gather issues and check for secure properties usage.

    The function aggregates all issues found across the files and determines if
    Mule Secure Properties configuration is used in at least one file within the project.

    Args:
        directory (str): The root directory to start searching for XML files.

    Returns:
        tuple[list[list[str]], bool]: A tuple containing:
            - A list of lists, where each inner list contains `[file_name, status_message, issue_description]`.
              This format is suitable for tabular display.
            - A boolean that is True if any file in the project contains Mule Secure
              Properties configuration (`<secure-properties:config>`), otherwise False.
    """
    all_issues_data = []  # Stores [file_name, status, issue_description] for all files
    project_uses_secure_properties = False  # Flag for overall project secure properties usage

    for root_dir, _, files in os.walk(directory):
        # Standard Mule project folders to exclude from review
        if 'target' in root_dir or 'test' in root_dir:
            continue  # Skip these directories

        for file_name in files:
            # Process only XML files, excluding pom.xml and MUnit test files
            if file_name.endswith('.xml') and file_name != 'pom.xml' and 'munit' not in file_name:
                file_path = os.path.join(root_dir, file_name)
                
                # Optional: Print statement for CLI progress; can be removed for library use.
                print(f"Reviewing file: {file_name}") 
                
                # Review individual file for issues and secure properties usage
                issues_for_file, found_secure_config_in_this_file = review_mulesoft_code(file_path)
                
                # If secure properties config found in this file, mark it for the project
                if found_secure_config_in_this_file:
                    project_uses_secure_properties = True
                
                # Aggregate results for reporting
                if issues_for_file:
                    for issue in issues_for_file:
                        all_issues_data.append([file_name, "Issue Found", issue])
                else:
                    # Record that the file was checked and had no issues.
                    # This maintains a consistent data structure for all_issues_data.
                    all_issues_data.append([file_name, "No Issues", ""])
    
    return all_issues_data, project_uses_secure_properties

# Example usage
#directory = 'C:/Users/yourname/ws/mulesoft/' + 'abc-xyz-integrationServices'

#review_all_files(directory)
