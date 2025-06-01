"""
This module provides functions to review MuleSoft XML configuration files for common
issues, adherence to naming conventions, and checks for specific configurations
like the use of Mule Secure Properties.
"""
import os
from lxml import etree
import re
# tabulate is not used in this module directly anymore, but was part of the original file.
# If other parts of the project rely on it being imported here, it could be kept,
# otherwise, it's a candidate for removal from this specific file's imports.
# For now, it's commented out as it's not used by functions in this module.
# from tabulate import tabulate 

def is_camel_case(name):
    """
    Checks if a given name is in camel case format.

    :param name: The name string to check.
    :return: True if the name is in camel case format, otherwise False.
    """
    return re.match(r'^[a-z][a-zA-Z0-9]*$', name) is not None

# Helper function to check for secure properties configuration
def _contains_secure_properties_config(root, namespaces):
    """
    Checks if the XML configuration contains a Mule Secure Properties <secure-properties:config> element.
    This indicates that the project is set up to use Mule's property encryption features.

    :param root: The root element of the parsed XML (lxml.etree._Element).
    :param namespaces: A dictionary of XML namespaces mapping prefixes to URIs.
    :return: True if a <secure-properties:config> element is found, otherwise False.
    """
    # XPath search for the secure-properties:config element.
    return root.find(".//secure-properties:config", namespaces=namespaces) is not None

def check_flow_names(root, namespaces):
    """
    Checks for issues with flow names in the XML configuration.
    - Flow names should comply with camel case format and contain only alphanumeric characters.

    :param root: The root element of the parsed XML.
    :param namespaces: A dictionary of XML namespaces used in the MuleSoft configuration.
    :return: A list of issues found related to flow names.
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
            elif not is_camel_case(name_to_check):
                issues.append(f"Flow name part '{name_to_check}' (from original: '{name}') does not comply with camel case format.")
            elif not re.match(r'^[a-zA-Z0-9]+$', name_to_check):
                issues.append(f"Flow name part '{name_to_check}' (from original: '{name}') contains invalid characters. It should be alphanumeric.")
    return issues

def check_http_listener(root, namespaces):
    """
    Checks for issues with HTTP Listener configurations.
    - HTTP Listeners should have a defined path attribute.

    :param root: The root element of the parsed XML.
    :param namespaces: A dictionary of XML namespaces used in the MuleSoft configuration.
    :return: A list of issues found related to HTTP Listeners.
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
    - Loggers should have a defined message attribute.

    :param root: The root element of the parsed XML.
    :param namespaces: A dictionary of XML namespaces used in the MuleSoft configuration.
    :return: A list of issues found related to Loggers.
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
    - DataWeave transformations should include a set-payload element.

    :param root: The root element of the parsed XML.
    :param namespaces: A dictionary of XML namespaces used in the MuleSoft configuration.
    :return: A list of issues found related to DataWeave transformations.
    """
    issues = []
    for transform in root.findall(".//dw:transform-message", namespaces=namespaces):
        set_payload = transform.find(".//dw:set-payload", namespaces=namespaces)
        if set_payload is None:
            issues.append("DataWeave transformation is missing a set-payload element.")
    return issues

def check_http_response(root, namespaces):
    """
    Checks for issues with HTTP Response Builders.
    - HTTP Response Builders should have a defined status-code element.

    :param root: The root element of the parsed XML.
    :param namespaces: A dictionary of XML namespaces used in the MuleSoft configuration.
    :return: A list of issues found related to HTTP Response Builders.
    """
    issues = []
    for response in root.findall(".//http:response-builder", namespaces=namespaces):
        status_code = response.find(".//http:status-code", namespaces=namespaces)
        if status_code is None:
            issues.append("HTTP Response Builder is missing a status-code element.")
    return issues

def check_scheduler(root, namespaces):
    """
    Checks for issues with Scheduler configurations.
    - Schedulers should have a defined frequency attribute.

    :param root: The root element of the parsed XML.
    :param namespaces: A dictionary of XML namespaces used in the MuleSoft configuration.
    :return: A list of issues found related to Schedulers.
    """
    issues = []
    for scheduler in root.findall(".//scheduler:inbound-endpoint", namespaces=namespaces):
        frequency = scheduler.get("frequency")
        if not frequency:
            issues.append("Scheduler is missing a frequency attribute.")
    return issues

def check_concur(root, namespaces):
    """
    Checks for issues with Concur connector configurations.
    - Concur connectors should have a defined config-ref attribute.

    :param root: The root element of the parsed XML.
    :param namespaces: A dictionary of XML namespaces used in the MuleSoft configuration.
    :return: A list of issues found related to Concur connectors.
    """
    issues = []
    for concur in root.findall(".//concur:connector", namespaces=namespaces):
        config_ref = concur.get("config-ref")
        if not config_ref:
            issues.append("Concur connector is missing a config-ref attribute.")
    return issues

def check_http_requester(root, namespaces):
    """
    Checks for issues with HTTP Requester configurations.
    - HTTP Requesters should have a defined URL attribute.

    :param root: The root element of the parsed XML.
    :param namespaces: A dictionary of XML namespaces used in the MuleSoft configuration.
    :return: A list of issues found related to HTTP Requesters.
    """
    issues = []
    for requester in root.findall(".//http:requester", namespaces=namespaces):
        url = requester.get("url")
        if not url:
            issues.append("HTTP Requester is missing a URL attribute.")
    return issues

def check_ftp(root, namespaces):
    """
    Checks for issues with FTP Inbound Endpoint configurations.
    - FTP Inbound Endpoints should have defined host and port attributes.

    :param root: The root element of the parsed XML.
    :param namespaces: A dictionary of XML namespaces used in the MuleSoft configuration.
    :return: A list of issues found related to FTP Inbound Endpoints.
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
    Checks for issues with SFTP Inbound Endpoint configurations.
    - SFTP Inbound Endpoints should have defined host and port attributes.

    :param root: The root element of the parsed XML.
    :param namespaces: A dictionary of XML namespaces used in the MuleSoft configuration.
    :return: A list of issues found related to SFTP Inbound Endpoints.
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
    Checks for issues with SMB configurations.
    - SMB components should have defined host, port, and username attributes.

    :param root: The root element of the parsed XML.
    :param namespaces: A dictionary of XML namespaces used in the MuleSoft configuration.
    :return: A list of issues found related to SMB configurations.
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
    Checks for issues with VM configurations.
    - VM components should have defined queue-name and max-retries attributes.

    :param root: The root element of the parsed XML.
    :param namespaces: A dictionary of XML namespaces used in the MuleSoft configuration.
    :return: A list of issues found related to VM configurations.
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
    Checks for issues with S3 Bucket configurations.
    - S3 Buckets should have defined bucket-name and access-key attributes.

    :param root: The root element of the parsed XML.
    :param namespaces: A dictionary of XML namespaces used in the MuleSoft configuration.
    :return: A list of issues found related to S3 Bucket configurations.
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
    Checks for issues with SMTP configurations.
    - SMTP components should have defined host, port, and username attributes.

    :param root: The root element of the parsed XML.
    :param namespaces: A dictionary of XML namespaces used in the MuleSoft configuration.
    :return: A list of issues found related to SMTP configurations.
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
    <secure-properties:config> element.

    :param file_path: The path to the XML file to review.
    :return: A tuple:
             - issues (list): A list of issue description strings found in the XML file.
             - uses_secure_config_in_file (bool): True if a <secure-properties:config>
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
        issues.extend(check_s3(root, namespaces))
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

    :param directory: The root directory to start searching for XML files.
    :return: A tuple:
             - all_issues_data (list): A list of lists, where each inner list contains
               [file_name, status_message, issue_description]. This format is
               suitable for tabular display.
             - project_uses_secure_properties (bool): True if any file in the project
               contains Mule Secure Properties configuration, otherwise False.
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
#directory = 'c:/work/rnd/mulesoft-temp/sbs-ott-triggerintegrator'
#directory = 'C:/Users/venkats/OneDrive - SBS Corporation/Documents/SBS/ws/mulesoft/' + 'sbs-mpx-mediamanagmentservices'
#directory = 'C:/Users/venkats/OneDrive - SBS Corporation/Documents/SBS/ws/mulesoft/' + 'sbs-tbs-ingestmediainfo'
#directory = 'C:/Users/venkats/OneDrive - SBS Corporation/Documents/SBS/ws/mulesoft/' + 'sbs-pnc-integrationservices'
#directory = 'C:/Users/venkats/OneDrive - SBS Corporation/Documents/SBS/ws/mulesoft/' + 'sbs-eis-integrationservices'

#review_all_files(directory)
