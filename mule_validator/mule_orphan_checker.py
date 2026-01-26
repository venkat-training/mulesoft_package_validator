"""
Module: mule_orphan_checker.py

This module provides functionality to scan a MuleSoft project for orphaned flows,
subflows, configurations, variables, property keys, error handlers, exception strategies,
endpoints, and DataWeave scripts. It produces JSON, HTML, and Bitbucket Markdown reports.

Changes:
- Added module- and function-level docstrings.
- Replaced print statements with logging calls.
- Removed duplicate code.
- Centralized magic strings and regex patterns.
- Enhanced exception handling and type hints.
- Added Bitbucket markdown report generation for PR comments.
"""

import os
import re
import xml.etree.ElementTree as ET
from typing import Set, List, Dict, Tuple, Any
from collections import defaultdict
import yaml
import logging
import json
from pathlib import Path

# Constants for regex patterns and reserved words
PROPERTY_PATTERNS = [
    r"p\(['\"]([a-zA-Z0-9_.:-]+)['\"]\)",
    r"#\[p\(['\"]([a-zA-Z0-9_.:-]+)['\"]\)\]",
    r"\$\{([a-zA-Z0-9_.:-]+)\}",
    r"secure::([a-zA-Z0-9_.:-]+)",
    r"default\s+p\(['\"]([a-zA-Z0-9_.:-]+)['\"]\)",
    r"Mule::p\(\s*['\"]([a-zA-Z0-9_.:-]+)['\"]\s*\)"
]
VARIABLE_PATTERNS = [
    r"#\[\s*vars\.([a-zA-Z_][a-zA-Z0-9_]*)\s*\]",
    r"vars\.([a-zA-Z_][a-zA-Z0-9_]*)",
    r"#\[\s*([a-zA-Z_][a-zA-Z0-9_]*)\s*\]",
    r"attributes\.headers\[['\"]([a-zA-Z0-9_-]+)['\"]\]",
    r"%X\{([a-zA-Z0-9_.-]+)\}"
]
RESERVED_WORDS = {
    "payload", "message", "attributes", "vars", "now", "null", "true", "false",
    "error", "logger", "request", "response", "dw", "as", "default", "output",
    "application", "java", "var", "if", "else", "map", "for", "while", "and", "or", "not"
}
CONTEXT_RESERVED = {"output", "application", "java", "as", "var", "default", "dw",
                    "true", "false", "null"}


class MuleComprehensiveOrphanChecker:
    """
    A checker class to scan MuleSoft projects for orphaned elements and generate reports.
    """

    def __init__(self, base_dir: str) -> None:
        """
        Initialize the checker by setting up directories, data structures, and logging.
        """
        self.base_dir = Path(base_dir)
        self.mule_dir = self.base_dir / "src" / "main" / "mule"
        self.resource_dir = self.base_dir / "src" / "main" / "resources"

        self.declared_flows: Dict[str, str] = {}
        self.referenced_flows: Set[str] = set()
        self.declared_subflows: Dict[str, str] = {}
        self.referenced_subflows: Set[str] = set()

        self.declared_configs: Set[str] = set()
        self.referenced_configs: Set[str] = set()

        self.declared_variables: Dict[str, Tuple[str, str]] = {}
        self.referenced_variables: Set[str] = set()

        self.declared_env_vars: Set[str] = set()
        self.referenced_env_vars: Set[str] = set()

        self.yaml_property_keys: Set[str] = set()
        self.yaml_property_keys_used: Set[str] = set()

        self.declared_error_handlers: Set[str] = set()
        self.referenced_error_handlers: Set[str] = set()
        self.declared_exception_strategies: Set[str] = set()
        self.referenced_exception_strategies: Set[str] = set()

        self.declared_endpoints: Set[str] = set()
        self.referenced_endpoints: Set[str] = set()

        self.declared_dw_scripts: Set[str] = set()
        self.referenced_dw_scripts: Set[str] = set()

        self.xml_files_processed: List[str] = []
        self.dwl_files_processed: List[str] = []
        self.yaml_files_processed: List[str] = []
        self.validation_errors: List[str] = []
        self._compile_regex_patterns()

        self.logger = logging.getLogger(__name__)
        logging.basicConfig(level=logging.INFO,
                            format='%(asctime)s - %(name)s - %(levelname)s - %(message)s')

    
    def _compile_regex_patterns(self) -> None:
        """Compile regex patterns for better performance during text extraction."""
        self.property_patterns = [
            re.compile(r"p\(['\"]([a-zA-Z0-9_.:-]+)['\"]\)"),
            re.compile(r"#\[p\(['\"]([a-zA-Z0-9_.:-]+)['\"]\)\]"),
            re.compile(r"\$\{([a-zA-Z0-9_.:-]+)\}"),
            re.compile(r"secure::([a-zA-Z0-9_.:-]+)"),
            re.compile(r"default\s+p\(['\"]([a-zA-Z0-9_.:-]+)['\"]\)"),
            re.compile(r"Mule::p\(\s*['\"]([a-zA-Z0-9_.:-]+)['\"]\s*\)")
        ]
        
        self.variable_patterns = [
            re.compile(r"#\[\s*vars\.([a-zA-Z_][a-zA-Z0-9_]*)\s*\]"),
            re.compile(r"vars\.([a-zA-Z_][a-zA-Z0-9_]*)"),
            re.compile(r"#\[\s*([a-zA-Z_][a-zA-Z0-9_]*)\s*\]"),
            re.compile(r"attributes\.headers\[['\"]([a-zA-Z0-9_-]+)['\"]\]"),
            re.compile(r"%X\{([a-zA-Z0-9_.-]+)\}")
        ]
        
        self.dw_block_pattern = re.compile(r"<!\[CDATA\[%dw.*?---(.*?)\]\]>", re.DOTALL)
        self.token_pattern = re.compile(r"\b([a-zA-Z_][a-zA-Z0-9_]*)\b")
        self.apikit_pattern = re.compile(r'^(get|post|put|delete|patch|options):')

    def run(self, html_output_path: str = None, bitbucket_md_path: str = None) -> Dict[str, Any]:
        """
        Run the complete scanning process and generate a comprehensive report.
        Optionally produces an HTML report and/or Bitbucket markdown at the specified output paths.
        """
        self.logger.info("Starting MuleSoft validation...")

        self._scan_xml_files()
        self._scan_yaml_keys()
        self._scan_dwl_files()
        self._scan_additional_files()

        report = self._generate_comprehensive_report()
        self.logger.info(f"Total orphaned items found: {report['summary']['total_orphaned_items']}")

        if html_output_path:
            self._generate_html_report(report, html_output_path)
        else:
            self._generate_html_report(report)
            
        if bitbucket_md_path:
            self._generate_bitbucket_markdown(report, bitbucket_md_path)
            
        return report

    def _scan_xml_files(self) -> None:
        """
        Recursively scan and process all Mule XML files, excluding test and target directories.
        """
        self.logger.info("Scanning all Mule XML files in the project directory recursively...")
    
        xml_files = [
            f for f in self.base_dir.glob("**/*.xml")
            if not any(exclude in str(f).replace("\\", "/") 
                    for exclude in ["src/test", "target", ".tooling-project"])
        ]
        
        self.logger.info(f"Found {len(xml_files)} XML files to process.")
        for xml_file in xml_files:
            try:
                self._parse_mule_xml(xml_file)
                self.xml_files_processed.append(str(xml_file.relative_to(self.base_dir)))
            except Exception as e:
                msg = f"Failed to parse {xml_file}: {e}"
                self.logger.error(msg, exc_info=True)
                self.validation_errors.append(msg)

    def _parse_mule_xml(self, filepath: Path) -> None:
        """
        Parse a Mule XML file to extract flows, subflows, configurations, variables, endpoints, etc.
        """
        try:
            with open(filepath, 'r', encoding='utf-8') as f:
                content = f.read()
                self._extract_references(content)
        except Exception as e:
            msg = f"Error reading file {filepath}: {e}"
            self.logger.error(msg, exc_info=True)
            self.validation_errors.append(msg)

        tree = ET.parse(filepath)
        root = tree.getroot()
        ns = {
            'm': 'http://www.mulesoft.org/schema/mule/core',
            'http': 'http://www.mulesoft.org/schema/mule/http',
            'dw': 'http://www.mulesoft.org/schema/mule/ee/dw'
        }

        # Process flows
        for flow in root.findall(".//m:flow", ns):
            name = flow.attrib.get("name")
            if name:
                self.declared_flows[name] = str(filepath.relative_to(self.base_dir))
            for set_var_tag in flow.findall(".//m:set-variable", ns):
                var_name = set_var_tag.attrib.get("variableName") or set_var_tag.attrib.get("name")
                if var_name:
                    self.declared_variables[var_name] = (name if name is not None else "<unknown flow>",
                                                         str(filepath.relative_to(self.base_dir)))
            if name and any(tag.tag.endswith("scheduler") or tag.tag.endswith("scheduling-strategy") for tag in flow.iter()):
                self.referenced_flows.add(name)
            if name and any("listener" in tag.tag for tag in flow.iter()):
                self.referenced_flows.add(name)

        # Process sub-flows
        for subflow in root.findall(".//m:sub-flow", ns):
            name = subflow.attrib.get("name")
            if name:
                self.declared_subflows[name] = str(filepath.relative_to(self.base_dir))
                for set_var_tag in subflow.findall(".//m:set-variable", ns):
                    var_name = set_var_tag.attrib.get("variableName") or set_var_tag.attrib.get("name")
                    if var_name:
                        self.declared_variables[var_name] = (name, str(filepath.relative_to(self.base_dir)))

        # Flow references
        for flowref in root.findall(".//m:flow-ref", ns):
            name = flowref.attrib.get("name")
            if name:
                self.referenced_flows.add(name)
                self.referenced_subflows.add(name)

        # Configs and references
        for tag in root.iter():
            tag_name = tag.tag.split('}')[-1] if '}' in tag.tag else tag.tag
            if tag_name.lower().endswith("config") or tag_name.lower().endswith("context"):
                name = tag.attrib.get("name")
                if name and not tag.tag.startswith("{http://www.mulesoft.org/schema/mule/secure-properties}"):
                    self.declared_configs.add(name)
            for attr_key, attr_val in tag.attrib.items():
                if attr_key in {"config-ref", "listener-config-ref", "request-config-ref", "context-ref"}:
                    self.referenced_configs.add(attr_val)
                    if ("listener" in attr_key.lower() or 
                        "listener" in tag.tag.lower() or 
                        tag.tag.endswith("listener")):
                        self.referenced_endpoints.add(attr_val)
                else:
                    self._extract_references(attr_val)
            if tag.text:
                self._extract_references(tag.text)

        # Error Handlers
        for err_handler in root.findall(".//m:error-handler", ns):
            name = err_handler.attrib.get("name")
            if name:
                self.declared_error_handlers.add(name)

        # Exception strategies
        for exc_strategy in root.findall(".//m:on-error-continue", ns) + root.findall(".//m:on-error-propagate", ns):
            ref = exc_strategy.attrib.get("ref")
            if ref:
                self.referenced_exception_strategies.add(ref)
            name = exc_strategy.attrib.get("name")
            if name:
                self.declared_exception_strategies.add(name)

        # HTTP Listener endpoints
        for http_listener in root.findall(".//http:listener-config", ns):
            name = http_listener.attrib.get("name")
            if name:
                self.declared_endpoints.add(name)

        # DataWeave transform references
        for transform in root.findall(".//m:transform", ns) + root.findall(".//dw:transform-message", ns):
            resource = transform.attrib.get("resource")
            if resource:
                self.referenced_dw_scripts.add(resource)

    def _extract_references(self, text: str) -> None:
        """
        Extract property keys and variable references from the provided text using regex patterns.
        """
        if not text:
            return

        for pattern in self.property_patterns:
            found_keys = re.findall(pattern, text)
            if pattern == r"Mule::p\(\s*['\"]([a-zA-Z0-9_.:-]+)['\"]\s*\)":
                logging.debug("Mule::p matches found in text: %s", found_keys)
            self.yaml_property_keys_used.update(k.strip().lower() for k in found_keys)

        for pattern in self.variable_patterns:
            for match in re.findall(pattern, text):
                if match not in RESERVED_WORDS:
                    self.referenced_variables.add(match)

        # DataWeave CDATA blocks extraction
        dw_blocks = re.findall(r"<!\[CDATA\[%dw.*?---(.*?)\]\]>", text, re.DOTALL)
        for dw in dw_blocks:
            for pattern in self.property_patterns:
                found_keys = re.findall(pattern, dw)
                if pattern == r"Mule::p\(\s*['\"]([a-zA-Z0-9_.:-]+)['\"]\s*\)":
                    logging.debug("Mule::p matches found in DWL: %s", found_keys)
                self.yaml_property_keys_used.update(k.strip().lower() for k in found_keys)
            tokens = re.findall(r"\b([a-zA-Z_][a-zA-Z0-9_]*)\b", dw)
            for token in tokens:
                if token in RESERVED_WORDS or token in CONTEXT_RESERVED:
                    continue
                if token in self.declared_variables:
                    self.referenced_variables.add(token)

    def _scan_yaml_keys(self) -> None:
        """
        Scan YAML files in the resources directory to extract property keys.
        """
        self.logger.info("Scanning YAML property files...")
        yaml_files = list(self.resource_dir.glob("*.yml")) + list(self.resource_dir.glob("*.yaml"))
        for yml in yaml_files:
            try:
                with open(yml, 'r') as f:
                    data = yaml.safe_load(f)
                    self._extract_yaml_keys(data)
                    self.yaml_files_processed.append(str(yml.relative_to(self.base_dir)))
            except yaml.YAMLError as e:
                msg = f"Failed to parse YAML {yml}: {e}"
                self.logger.error(msg, exc_info=True)
                self.validation_errors.append(msg)

    def _extract_yaml_keys(self, data: Any, prefix: str = '') -> None:
        """
        Recursively extract YAML keys and add them to the declared property keys set.
        """
        if isinstance(data, dict):
            for key, value in data.items():
                full_key = f"{prefix}.{key}" if prefix else key
                full_key_lower = full_key.strip().lower()
                if not isinstance(value, dict):
                    self.yaml_property_keys.add(full_key_lower)
                self._extract_yaml_keys(value, full_key)
        elif isinstance(data, list):
            for item in data:
                self._extract_yaml_keys(item, prefix)

    def _scan_dwl_files(self) -> None:
        """
        Scan DataWeave (.dwl) files from the Mule directory and additional module directories.
        """
        self.logger.info("Scanning DataWeave files...")
        dwl_files = list(self.mule_dir.glob("**/*.dwl"))
        
        # Also scan src/main/resources/modules for DWL files
        modules_dir = self.base_dir / "src" / "main" / "resources" / "modules"
        if modules_dir.exists():
            dwl_files += list(modules_dir.glob("**/*.dwl"))
        
        # Filter out excluded directories
        dwl_files = [
            f for f in dwl_files
            if not any(exclude in str(f).replace("\\", "/") 
                    for exclude in ["src/test", "target", ".tooling-project"])
        ]
        
        self.logger.info(f"Found {len(dwl_files)} DataWeave files to process.")
        for file in dwl_files:
            try:
                self.declared_dw_scripts.add(str(file.relative_to(self.base_dir)))
                with open(file, 'r', encoding='utf-8') as f:
                    text = f.read()
                    self._extract_references(text)
                    self.dwl_files_processed.append(str(file.relative_to(self.base_dir)))
            except Exception as e:
                msg = f"Failed to parse DWL {file}: {e}"
                self.logger.error(msg, exc_info=True)
                self.validation_errors.append(msg)

    def _scan_additional_files(self) -> None:
        """
        Scan additional files (HTML and JS) for potential references.
        """
        text_files = list(self.base_dir.glob("**/*.html")) + list(self.base_dir.glob("**/*.js"))
    
        # Filter out test files, target, and .tooling-project directories
        text_files = [
            f for f in text_files 
            if not any(exclude in str(f).replace("\\", "/") 
                    for exclude in ["src/test", "target", ".tooling-project", "node_modules"])
        ]
        
        self.logger.info(f"Found {len(text_files)} additional files to scan for references.")
        for file in text_files:
            try:
                # Use utf-8 encoding with error handling
                with open(file, 'r', encoding='utf-8', errors='ignore') as f:
                    text = f.read()
                    self._extract_references(text)
            except Exception as e:
                msg = f"Failed to parse {file}: {e}"
                self.logger.error(msg, exc_info=True)
                self.validation_errors.append(msg)

    def _find_orphans(self, declared: Set[str], referenced: Set[str]) -> Tuple[List[str], List[str]]:
        """
        Identify orphaned and used items by comparing declared and referenced sets.
        """
        used = sorted(list(declared & referenced))
        orphan = sorted(list(declared - referenced))
        return orphan, used

    def _generate_comprehensive_report(self) -> Dict[str, Any]:
        """
        Generate a comprehensive report in JSON format with summaries of orphans, used, and declared items.
        """
        # ADD EXTENSIVE DEBUG LOGGING
        self.logger.info("="*80)
        self.logger.info("STARTING REPORT GENERATION - DEBUG INFO")
        self.logger.info("="*80)
        
        self.logger.info(f"Declared flows: {len(self.declared_flows)}")
        self.logger.info(f"Declared flows list: {list(self.declared_flows.keys())}")
        self.logger.info(f"Referenced flows: {len(self.referenced_flows)}")
        self.logger.info(f"Referenced flows list: {list(self.referenced_flows)}")
        
        self.logger.info(f"Declared subflows: {len(self.declared_subflows)}")
        self.logger.info(f"Declared subflows list: {list(self.declared_subflows.keys())}")
        self.logger.info(f"Referenced subflows: {len(self.referenced_subflows)}")
        self.logger.info(f"Referenced subflows list: {list(self.referenced_subflows)}")
        
        self.logger.info(f"Declared configs: {len(self.declared_configs)}")
        self.logger.info(f"Declared configs list: {list(self.declared_configs)}")
        self.logger.info(f"Referenced configs: {len(self.referenced_configs)}")
        self.logger.info(f"Referenced configs list: {list(self.referenced_configs)}")
        
        self.logger.info(f"Declared property keys: {len(self.yaml_property_keys)}")
        self.logger.info(f"Used property keys: {len(self.yaml_property_keys_used)}")
        
        self.logger.info(f"Declared variables: {len(self.declared_variables)}")
        self.logger.info(f"Referenced variables: {len(self.referenced_variables)}")
        
        # Calculate APIKit flows
        apikit_flows = self._apikit_derived_flows()
        self.logger.info(f"APIKit derived flows: {len(apikit_flows)}")
        self.logger.info(f"APIKit flows list: {list(apikit_flows)}")
        
        orphan_flows_list, used_flows = self._find_orphans(
            set(self.declared_flows.keys()), 
            self.referenced_flows | apikit_flows
        )
        
        self.logger.info(f"ORPHAN FLOWS FOUND: {len(orphan_flows_list)}")
        self.logger.info(f"Orphan flows list: {orphan_flows_list}")
        
        orphan_subflows_list, used_subflows = self._find_orphans(
            set(self.declared_subflows.keys()), self.referenced_subflows
        )
        
        self.logger.info(f"ORPHAN SUBFLOWS FOUND: {len(orphan_subflows_list)}")
        self.logger.info(f"Orphan subflows list: {orphan_subflows_list}")
        
        orphan_configs, used_configs = self._find_orphans(self.declared_configs, self.referenced_configs)
        
        self.logger.info(f"ORPHAN CONFIGS FOUND: {len(orphan_configs)}")
        self.logger.info(f"Orphan configs list: {orphan_configs}")
        
        orphan_vars_list, used_vars = self._find_orphans(set(self.declared_variables.keys()), self.referenced_variables)
        orphan_env_vars, used_env_vars = self._find_orphans(self.declared_env_vars, self.referenced_env_vars)
        orphan_props, used_props = self._find_orphans(self.yaml_property_keys, self.yaml_property_keys_used)
        
        self.logger.info(f"ORPHAN PROPERTY KEYS FOUND: {len(orphan_props)}")
        self.logger.info(f"Orphan props list (first 10): {list(orphan_props)[:10]}")
        
        orphan_error_handlers, used_error_handlers = self._find_orphans(self.declared_error_handlers, self.referenced_error_handlers)
        orphan_exc_strategies, used_exc_strategies = self._find_orphans(self.declared_exception_strategies, self.referenced_exception_strategies)
        orphan_endpoints, used_endpoints = self._find_orphans(self.declared_endpoints, self.referenced_endpoints)
        orphan_dw_scripts, used_dw_scripts = self._find_orphans(self.declared_dw_scripts, self.referenced_dw_scripts)

        orphan_flows = [(flow, self.declared_flows[flow]) for flow in orphan_flows_list]
        used_flows_detailed = [(flow, self.declared_flows.get(flow, "Unknown file")) for flow in used_flows]
        orphan_subflows = [(name, self.declared_subflows[name]) for name in orphan_subflows_list]
        used_subflows_detailed = [(subflow, self.declared_subflows.get(subflow, "Unknown file")) for subflow in used_subflows]
        orphan_vars = [(var, flow, file) for var, (flow, file) in self.declared_variables.items() if var in orphan_vars_list]
        used_vars_detailed = [(var, self.declared_variables[var][0], self.declared_variables[var][1]) for var in used_vars]

        total_orphans = (
            len(orphan_flows) + 
            len(orphan_subflows) + 
            len(orphan_configs) + 
            len(orphan_vars) +
            len(orphan_env_vars) + 
            len(orphan_props) + 
            len(orphan_error_handlers) + 
            len(orphan_exc_strategies) +
            len(orphan_endpoints) + 
            len(orphan_dw_scripts)
        )
        
        self.logger.info("="*80)
        self.logger.info(f"TOTAL ORPHANED ITEMS: {total_orphans}")
        self.logger.info("="*80)

        summary = {
            "total_orphaned_items": total_orphans,
            "orphan_flows_count": len(orphan_flows),
            "orphan_subflows_count": len(orphan_subflows),
            "orphan_configs_count": len(orphan_configs),
            "orphan_variables_count": len(orphan_vars),
            "orphan_env_vars_count": len(orphan_env_vars),
            "orphan_property_keys_count": len(orphan_props),
            "orphan_error_handlers_count": len(orphan_error_handlers),
            "orphan_exception_strategies_count": len(orphan_exc_strategies),
            "orphan_endpoints_count": len(orphan_endpoints),
            "orphan_dw_scripts_count": len(orphan_dw_scripts),
        }

        report = {
            "summary": summary,
            "orphans": {
                "flows": orphan_flows,
                "subflows": orphan_subflows,
                "configs": list(orphan_configs),
                "variables": orphan_vars,
                "env_vars": list(orphan_env_vars),
                "property_keys": list(orphan_props),
                "error_handlers": list(orphan_error_handlers),
                "exception_strategies": list(orphan_exc_strategies),
                "endpoints": list(orphan_endpoints),
                "dw_scripts": list(orphan_dw_scripts)
            },
            "used": {
                "flows": used_flows_detailed,
                "subflows": used_subflows_detailed,
                "configs": list(used_configs),
                "variables": used_vars_detailed,
                "env_vars": list(used_env_vars),
                "property_keys": list(used_props),
                "error_handlers": list(used_error_handlers),
                "exception_strategies": list(used_exc_strategies),
                "endpoints": list(used_endpoints),
                "dw_scripts": list(used_dw_scripts)
            },
            "declared": {
                "flows": sorted(list(self.declared_flows.keys())),
                "subflows": sorted([(k, v) for k, v in self.declared_subflows.items()]),
                "configs": sorted(list(self.declared_configs)),
                "variables": sorted([(k, v[0], v[1]) for k, v in self.declared_variables.items()]),
                "env_vars": sorted(list(self.declared_env_vars)),
                "property_keys": sorted(list(self.yaml_property_keys)),
                "error_handlers": sorted(list(self.declared_error_handlers)),
                "exception_strategies": sorted(list(self.declared_exception_strategies)),
                "endpoints": sorted(list(self.declared_endpoints)),
                "dw_scripts": sorted(list(self.declared_dw_scripts))
            },
            "files_processed": {
                "xml_files": self.xml_files_processed,
                "dwl_files": self.dwl_files_processed,
                "yaml_files": self.yaml_files_processed,
            },
            "validation_errors": self.validation_errors
        }

        # SAVE REPORT TO JSON FILE FOR DEBUGGING
        try:
            with open('orphan_report_debug.json', 'w', encoding='utf-8') as f:
                json.dump(report, f, indent=2)
            self.logger.info("Debug JSON report saved to: orphan_report_debug.json")
        except Exception as e:
            self.logger.error(f"Failed to save debug JSON: {e}")

        return report

    def _apikit_derived_flows(self) -> Set[str]:
        """
        Derive flows from APIkit naming conventions.
        """
        #return {name for name in self.declared_flows if re.match(r'^(get|post|put|delete|patch|options):', name)}
        return {name for name in self.declared_flows if self.apikit_pattern.match(name)}

    def _generate_bitbucket_markdown(self, report: Dict[str, Any], output_path: str = "bitbucket-comment.md") -> None:
        """
        Generate a Bitbucket-formatted markdown summary for PR comments.
        """
        md = []
        summary = report["summary"]
        orphan_count = summary["total_orphaned_items"]
        
        # Header with status
        if orphan_count == 0:
            status_icon = "✅"
            status = "PASSED"
            status_color = "🟢"
            message = "All MuleSoft components are properly referenced and in use. No cleanup required!"
        else:
            status_icon = "⚠️"
            status = "REVIEW NEEDED"
            status_color = "🟡"
            message = f"Found {orphan_count} orphaned item(s) that may need attention."
        
        md.append("## 🔍 MuleSoft Orphan Checker Report\n")
        md.append(f"{status_color} **Status:** {status} {status_icon}\n")
        md.append(f"\n### 📊 Summary\n")
        md.append(f"\n**Total Orphaned Items:** `{orphan_count}`\n")
        
        # Build comparison table
        md.append("\n| Component Type | Orphaned | In Use |")
        md.append("\n|----------------|----------|--------|")
        md.append(f"\n| Flows | {summary['orphan_flows_count']} | {len(report['used']['flows'])} |")
        md.append(f"\n| Subflows | {summary['orphan_subflows_count']} | {len(report['used']['subflows'])} |")
        md.append(f"\n| Configurations | {summary['orphan_configs_count']} | {len(report['used']['configs'])} |")
        md.append(f"\n| Variables | {summary['orphan_variables_count']} | {len(report['used']['variables'])} |")
        md.append(f"\n| Environment Variables | {summary['orphan_env_vars_count']} | {len(report['used']['env_vars'])} |")
        md.append(f"\n| Property Keys | {summary['orphan_property_keys_count']} | {len(report['used']['property_keys'])} |")
        md.append(f"\n| Error Handlers | {summary['orphan_error_handlers_count']} | {len(report['used']['error_handlers'])} |")
        md.append(f"\n| DataWeave Scripts | {summary['orphan_dw_scripts_count']} | {len(report['used']['dw_scripts'])} |")
        md.append(f"\n| Endpoints | {summary['orphan_endpoints_count']} | {len(report['used']['endpoints'])} |")
        
        # Add orphan details if any exist
        if orphan_count > 0:
            md.append("\n\n### ⚠️ Orphaned Items Details\n")
            
            if summary['orphan_flows_count'] > 0:
                md.append(f"\n**Flows ({summary['orphan_flows_count']}):**")
                for flow, file_path in report['orphans']['flows'][:5]:
                    md.append(f"\n- `{flow}` in `{file_path}`")
                if summary['orphan_flows_count'] > 5:
                    md.append(f"\n- _(and {summary['orphan_flows_count'] - 5} more)_")
            
            if summary['orphan_configs_count'] > 0:
                md.append(f"\n\n**Configurations ({summary['orphan_configs_count']}):**")
                for config in list(report['orphans']['configs'])[:5]:
                    md.append(f"\n- `{config}`")
                if summary['orphan_configs_count'] > 5:
                    md.append(f"\n- _(and {summary['orphan_configs_count'] - 5} more)_")
            
            if summary['orphan_variables_count'] > 0:
                md.append(f"\n\n**Variables ({summary['orphan_variables_count']}):**")
                for var, flow, file_path in report['orphans']['variables'][:5]:
                    md.append(f"\n- `{var}` in flow `{flow}`")
                if summary['orphan_variables_count'] > 5:
                    md.append(f"\n- _(and {summary['orphan_variables_count'] - 5} more)_")
            
            if summary['orphan_property_keys_count'] > 0:
                md.append(f"\n\n**Property Keys ({summary['orphan_property_keys_count']}):**")
                for prop in list(report['orphans']['property_keys'])[:5]:
                    md.append(f"\n- `{prop}`")
                if summary['orphan_property_keys_count'] > 5:
                    md.append(f"\n- _(and {summary['orphan_property_keys_count'] - 5} more)_")
        
        # Files analyzed
        md.append(f"\n\n### 📦 Files Analyzed")
        md.append(f"\n- **XML Files:** {len(report['files_processed']['xml_files'])}")
        md.append(f"\n- **DataWeave Files:** {len(report['files_processed']['dwl_files'])}")
        md.append(f"\n- **YAML Files:** {len(report['files_processed']['yaml_files'])}")
        
        md.append(f"\n\n{message}")
        
        # Validation errors if any
        if report['validation_errors']:
            md.append(f"\n\n### ⚠️ Validation Warnings ({len(report['validation_errors'])})")
            for err in report['validation_errors'][:3]:
                md.append(f"\n- {err}")
            if len(report['validation_errors']) > 3:
                md.append(f"\n- _(and {len(report['validation_errors']) - 3} more)_")
        
        md.append("\n\n---")
        md.append("\n\n📄 **Download full HTML report from Pipeline Artifacts** • Generated by MuleSoft Orphan Checker")
        
        try:
            with open(output_path, 'w', encoding='utf-8') as f:
                f.write(''.join(md))
            self.logger.info(f"Bitbucket markdown report generated at {output_path}")
        except Exception as e:
            self.logger.error(f"Failed to write Bitbucket markdown report at {output_path}: {e}", exc_info=True)

    def _generate_html_report(self, report: Dict[str, Any], output_path: str = "orphan_report.html") -> None:
        """
        Generate an HTML report from the given JSON report.
        """
        html = ['<html><head><meta charset="UTF-8"><title>MuleSoft Orphan Report</title>']
        html.append("""
        <style>
        body { font-family: Arial, sans-serif; margin: 20px; }
        h1, h2 { color: #333; }
        summary { font-weight: bold; cursor: pointer; }
        details { margin-bottom: 1em; }
        code { background: #f5f5f5; padding: 2px 6px; border-radius: 4px; display: inline-block; }
        .orphan { color: red; }
        .used { color: green; }
        .declared { color: #555; }
        </style>
        </head><body>
        """)
        html.append('<h1>MuleSoft Orphan Report</h1>')
        html.append('<h2>Summary</h2><ul>')
        for k, v in report["summary"].items():
            html.append(f"<li><b>{k}:</b> {v}</li>")
        html.append("</ul>")

        def build_section(title: str, data: Dict[str, List[Any]], css_class: str) -> None:
            html.append(f"<h2>{title}</h2>")
            for section, items in data.items():
                html.append(f"<details><summary>{section} ({len(items)})</summary><ul>")
                for item in items:
                    if section in {"flows", "subflows"}:
                        if isinstance(item, tuple):
                            name, file_path = item
                            html.append(f"<li><code class='{css_class}'>{name}</code> — <small>{file_path}</small></li>")
                        else:
                            html.append(f"<li><code class='{css_class}'>{item}</code></li>")
                    elif section == "variables":
                        var_name, flow_name, file_path = item
                        html.append(f"<li><code class='{css_class}'>{var_name}</code> — <small>Flow: {flow_name}, File: {file_path}</small></li>")
                    else:
                        html.append(f"<li><code class='{css_class}'>{item}</code></li>")
                html.append("</ul></details>")

        build_section("🛑 Orphan Items", report["orphans"], "orphan")
        build_section("✅ Used Items", report["used"], "used")
        build_section("📦 Declared Items", report["declared"], "declared")

        html.append("<h2>📄 Files Processed</h2><ul>")
        for ftype, files in report["files_processed"].items():
            html.append(f"<li>{ftype} ({len(files)}):")
            html.append("<ul>")
            for f in files:
                html.append(f"<li><code>{f}</code></li>")
            html.append("</ul></li>")
        html.append("</ul>")

        if report["validation_errors"]:
            html.append("<h2 style='color:red;'>⚠️ Validation Errors</h2><ul>")
            for err in report["validation_errors"]:
                html.append(f"<li>{err}</li>")
            html.append("</ul>")

        html.append("</body></html>")

        try:
            with open(output_path, 'w', encoding='utf-8') as f:
                f.write('\n'.join(html))
            self.logger.info(f"HTML report generated at {output_path}")
        except Exception as e:
            self.logger.error(f"Failed to write HTML report at {output_path}: {e}", exc_info=True)

def main() -> None:
    """
    Parse command line arguments and execute the MuleSoft orphan checker.
    """
    import argparse
    parser = argparse.ArgumentParser(description="MuleSoft Orphan Checker")
    parser.add_argument("project_dir", help="Path to MuleSoft project root")
    parser.add_argument("--html", help="Optional: Path to output HTML report", required=False)
    parser.add_argument("--bitbucket-md", help="Optional: Path to output Bitbucket markdown comment", required=False)
    args = parser.parse_args()
    checker = MuleComprehensiveOrphanChecker(args.project_dir)
    checker.run(html_output_path=args.html, bitbucket_md_path=args.bitbucket_md)

if __name__ == "__main__":
    main()