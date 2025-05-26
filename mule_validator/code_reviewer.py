import os
from lxml import etree
import re
import logging

# Configure logging
logger = logging.getLogger(__name__)

# Define Module-Level Constants
MULE_NAMESPACES = {
    'http': 'http://www.mulesoft.org/schema/mule/http', # Corrected http namespace
    'dw': 'http://www.mulesoft.org/schema/mule/ee/dw',
    'mule': 'http://www.mulesoft.org/schema/mule/core',
    'scheduler': 'http://www.mulesoft.org/schema/mule/schedulers', # Corrected scheduler namespace
    'concur': 'http://www.mulesoft.org/schema/mule/concur', # Assuming this is a custom or older namespace
    'ftp': 'http://www.mulesoft.org/schema/mule/ftp',
    'sftp': 'http://www.mulesoft.org/schema/mule/sftp',
    'smb': 'http://www.mulesoft.org/schema/mule/smb', # Assuming this is a custom or older namespace
    'vm': 'http://www.mulesoft.org/schema/mule/vm',
    's3': 'http://www.mulesoft.org/schema/mule/s3', # Assuming this is a custom or older namespace
    'smtp': 'http://www.mulesoft.org/schema/mule/smtp',
    'apikit': 'http://www.mulesoft.org/schema/mule/apikit', # Added for potential APIKit checks
    'ee': 'http://www.mulesoft.org/schema/mule/ee/core' # Common for Try, Scatter-Gather etc.
}
CAMEL_CASE_REGEX = r'^[a-z][a-zA-Z0-9]*$'
FLOW_NAME_VALID_CHAR_REGEX = r'^[a-zA-Z0-9]+$'
DEFAULT_SCAN_PATH_NAME = "src/main/mule"
EXCLUDED_DIRS = ('target', 'test')
EXCLUDED_FILE_SUBSTRINGS = ('munit',)
POM_XML_FILE_NAME = 'pom.xml'


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
    - Flow names should comply with camel case format and contain only alphanumeric characters.

    :param root: The root element of the parsed XML.
    :return: A list of issue description strings.
    """
    issues = []
    for flow in root.findall(".//mule:flow", namespaces=MULE_NAMESPACES):
        name = flow.get("name")
        if not name:
            issues.append("Flow is missing a name attribute.")
        elif not is_camel_case(name):
            issues.append(f"Flow name '{name}' does not comply with camel case format.")
        elif not re.match(FLOW_NAME_VALID_CHAR_REGEX, name): # Using FLOW_NAME_VALID_CHAR_REGEX
            issues.append(f"Flow name '{name}' contains invalid characters (only alphanumeric allowed).")
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
    - DataWeave transformations should include a dw:set-payload element.

    :param root: The root element of the parsed XML.
    :return: A list of issue description strings.
    """
    issues = []
    for transform in root.findall(".//dw:transform-message", namespaces=MULE_NAMESPACES):
        # Check within the transform-message element itself for set-payload
        set_payload = transform.find("./dw:set-payload", namespaces=MULE_NAMESPACES)
        if set_payload is None:
            issues.append("DataWeave transform-message is missing a direct dw:set-payload child.")
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
    Reviews a MuleSoft XML configuration file for common issues.
    Reads the XML file, parses it, and performs various checks.

    :param file_path: The path to the XML file to review.
    :return: A list of dictionaries. Each dictionary represents an issue found
             (keys: 'file_path', 'type', 'message') or an error encountered
             during processing. Returns an empty list if no issues are found
             and no errors occur.
    """
    logger.debug(f"Attempting to review MuleSoft code in file: {file_path}")
    issues_found = []
    try:
        with open(file_path, 'rb') as file: # Read as bytes for lxml
            xml_bytes = file.read()
        
        if not xml_bytes:
            logger.warning(f"File is empty: {file_path}")
            return [{'file_path': file_path, 'type': 'FileReadError', 'message': 'File is empty.'}]

        root = etree.fromstring(xml_bytes)
        
        # Perform checks using the global MULE_NAMESPACES
        # Note: Some checks might need to be more specific based on actual connector usage
        # and whether attributes are direct or on a referenced config.
        check_functions = [
            check_flow_names, check_http_listener, check_logger, check_dataweave,
            check_http_response, check_scheduler, check_concur, check_http_requester,
            check_ftp, check_sftp, check_smb, check_vm, check_s3, check_smtp
        ]

        for check_func in check_functions:
            try:
                results = check_func(root)
                for issue_message in results:
                    issues_found.append({
                        'file_path': file_path,
                        'type': 'CodeReviewIssue',
                        'message': f"{check_func.__name__}: {issue_message}" # Add context of which check failed
                    })
            except Exception as e: # Catch errors within a check function
                logger.error(f"Error during {check_func.__name__} for file {file_path}: {e}", exc_info=True)
                issues_found.append({
                    'file_path': file_path,
                    'type': 'CheckFunctionError',
                    'message': f"Error in {check_func.__name__}: {e}"
                })

        if not issues_found:
            logger.debug(f"No issues found in {file_path}")
        
        return issues_found

    except (IOError, OSError) as e:
        logger.error(f"File read error for {file_path}: {e}", exc_info=True)
        return [{'file_path': file_path, 'type': 'FileReadError', 'message': str(e)}]
    except etree.XMLSyntaxError as e:
        logger.error(f"XML syntax error in file {file_path}: {e}", exc_info=True)
        return [{'file_path': file_path, 'type': 'XMLSyntaxError', 'message': str(e)}]

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
