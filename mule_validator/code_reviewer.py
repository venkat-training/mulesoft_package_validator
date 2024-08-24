import os
from lxml import etree
import re
from tabulate import tabulate

def is_camel_case(name):
    """
    Checks if a given name is in camel case format.

    :param name: The name string to check.
    :return: True if the name is in camel case format, otherwise False.
    """
    return re.match(r'^[a-z][a-zA-Z0-9]*$', name) is not None

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
        elif not is_camel_case(name):
            issues.append(f"Flow name '{name}' does not comply with camel case format.")
        elif not re.match(r'^[a-zA-Z0-9]+$', name):
            issues.append(f"Flow name '{name}' contains invalid characters.")
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
    Reviews MuleSoft XML configuration file for common issues.
    - Reads the XML file, parses it, and performs various checks based on MuleSoft standards.

    :param file_path: The path to the XML file to review.
    :return: A list of issues found in the XML file.
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
            'smtp': 'http://www.mulesoft.org/schema/mule/smtp'
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
        issues.extend(check_smtp(root, namespaces))
        
        return issues
    except etree.XMLSyntaxError as e:
        return [f"XML Syntax Error in file {file_path}: {str(e)}"]
    except Exception as e:
        return [f"Error processing file {file_path}: {str(e)}"]

def review_all_files(directory):
    """
    Recursively reviews all XML files in the specified directory, ignoring files in 'target', 'test', and 'munit' folders.
    - Calls review_mulesoft_code for each XML file and prints the results in a tabular format.

    :param directory: The root directory to start searching for XML files.
    """
    table = []
    for root_dir, _, files in os.walk(directory):
        # Skip processing files in 'target' or 'test' folders
        if 'target' in root_dir or 'test' in root_dir:
            continue
        for file_name in files:
            if file_name.endswith('.xml') and file_name != 'pom.xml' and 'munit' not in file_name:
                file_path = os.path.join(root_dir, file_name)
                print(f"Reviewing file: {file_name}")
                issues = review_mulesoft_code(file_path)
                if issues:
                    for issue in issues:
                        table.append([file_name, "Issue Found", issue])
                else:
                    table.append([file_name, "No Issues", ""])
    
    # Print results in a tabular format
    print(tabulate(table, headers=["File Name", "Status", "Issue"], tablefmt="grid"))
    #return tabulate(table, headers=["File Name", "Status", "Issue"], tablefmt="grid")

# Example usage
#directory = 'c:/work/rnd/mulesoft-temp/sbs-ott-triggerintegrator'
#directory = 'C:/Users/venkats/OneDrive - SBS Corporation/Documents/SBS/ws/mulesoft/' + 'sbs-mpx-mediamanagmentservices'
#directory = 'C:/Users/venkats/OneDrive - SBS Corporation/Documents/SBS/ws/mulesoft/' + 'sbs-tbs-ingestmediainfo'
#directory = 'C:/Users/venkats/OneDrive - SBS Corporation/Documents/SBS/ws/mulesoft/' + 'sbs-pnc-integrationservices'
#directory = 'C:/Users/venkats/OneDrive - SBS Corporation/Documents/SBS/ws/mulesoft/' + 'sbs-eis-integrationservices'

#review_all_files(directory)
