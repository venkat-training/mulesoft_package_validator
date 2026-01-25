"""
MuleSoft Comprehensive Orphan Checker

This module provides functionality to identify orphaned (unused) components in MuleSoft applications,
including flows, subflows, configurations, variables, property keys, and other resources.

The checker analyzes XML configuration files, YAML property files, and DataWeave scripts to determine
which declared components are actually referenced and used within the application.
"""

import os
import re
import xml.etree.ElementTree as ET
from typing import Set, List, Dict, Tuple, Optional
from collections import defaultdict
import yaml
import logging
import json
from pathlib import Path

class MuleComprehensiveOrphanChecker:
    """
    Comprehensive orphan checker for MuleSoft applications.
    
    This class analyzes MuleSoft projects to identify orphaned (unused) components including:
    - Flows and subflows
    - Configuration objects
    - Variables
    - Property keys from YAML files
    - Error handlers and exception strategies
    - HTTP endpoints
    - DataWeave scripts
    
    Args:
        base_dir: Root directory of the MuleSoft project to analyze
    """
    
    def __init__(self, base_dir: str) -> None:
        """Initialize the orphan checker with project directory and data structures."""
        self.base_dir = Path(base_dir)
        self.mule_dir = self.base_dir / "src" / "main" / "mule"
        self.resource_dir = self.base_dir / "src" / "main" / "resources"

        # Flow tracking
        self.declared_flows: Dict[str, str] = {}  # flow_name -> xml_file
        self.referenced_flows: Set[str] = set()
        self.declared_subflows: Dict[str, str] = {}
        self.referenced_subflows: Set[str] = set()

        # Configuration tracking
        self.declared_configs: Set[str] = set()
        self.referenced_configs: Set[str] = set()

        # Variable tracking
        self.declared_variables: Dict[str, Tuple[str, str]] = {}  # var_name -> (flow_name, xml_file)
        self.referenced_variables: Set[str] = set()

        # Environment variable tracking
        self.declared_env_vars: Set[str] = set()
        self.referenced_env_vars: Set[str] = set()

        # Property key tracking
        self.yaml_property_keys: Set[str] = set()
        self.yaml_property_keys_used: Set[str] = set()

        # Error handling tracking
        self.declared_error_handlers: Set[str] = set()
        self.referenced_error_handlers: Set[str] = set()
        self.declared_exception_strategies: Set[str] = set()
        self.referenced_exception_strategies: Set[str] = set()

        # Endpoint tracking
        self.declared_endpoints: Set[str] = set()
        self.referenced_endpoints: Set[str] = set()

        # DataWeave script tracking
        self.declared_dw_scripts: Set[str] = set()
        self.referenced_dw_scripts: Set[str] = set()

        # Processing tracking
        self.xml_files_processed: List[str] = []
        self.dwl_files_processed: List[str] = []
        self.yaml_files_processed: List[str] = []
        self.validation_errors: List[str] = []

        # Compiled regex patterns for performance
        self._compile_regex_patterns()

        self.logger = logging.getLogger(__name__)
        
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

    def run(self, html_output_path: Optional[str] = None) -> Dict:
        """
        Execute the comprehensive orphan analysis.
        
        Args:
            html_output_path: Optional path to save HTML report
            
        Returns:
            Dictionary containing the complete analysis report
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
        return report

    def _scan_xml_files(self) -> None:
        """Scan all XML files in the project for Mule configurations and component declarations."""
        self.logger.info("Scanning all Mule XML files in the project directory recursively...")
        xml_files = [f for f in self.base_dir.glob("**/*.xml")
                     if "src/test" not in str(f).replace("\\", "/") and "target" not in str(f).replace("\\", "/")]
        self.logger.info(f"Found {len(xml_files)} XML files to process.")
        for xml_file in xml_files:
            try:
                self._parse_mule_xml(xml_file)
                self.xml_files_processed.append(str(xml_file.relative_to(self.base_dir)))
            except Exception as e:
                msg = f"Failed to parse {xml_file}: {e}"
                self.logger.error(msg)
                self.validation_errors.append(msg)

    def _parse_mule_xml(self, filepath: Path) -> None:
        """
        Parse a single Mule XML file to extract component declarations and references.
        
        Args:
            filepath: Path to the XML file to parse
        """
        with open(filepath, 'r', encoding='utf-8') as f:
            content = f.read()
            self._extract_references(content)

        tree = ET.parse(filepath)
        root = tree.getroot()
        ns = {
            'm': 'http://www.mulesoft.org/schema/mule/core',
            'http': 'http://www.mulesoft.org/schema/mule/http',
            'dw': 'http://www.mulesoft.org/schema/mule/ee/dw'
        }

        # Flows
        for flow in root.findall(".//m:flow", ns):
            name = flow.attrib.get("name")
            if name:
                self.declared_flows[name] = str(filepath.relative_to(self.base_dir))
            for set_var_tag in flow.findall(".//m:set-variable", ns):
                var_name = set_var_tag.attrib.get("variableName") or set_var_tag.attrib.get("name")
                if var_name:
                    self.declared_variables[var_name] = ((name if name is not None else "<unknown flow>"), str(filepath.relative_to(self.base_dir)))

            # If flow contains scheduler or listener tags, consider it referenced (triggered externally)
            if name and any(tag.tag.endswith("scheduler") or tag.tag.endswith("scheduling-strategy") for tag in flow.iter()):
                self.referenced_flows.add(name)
            if name and any("listener" in tag.tag for tag in flow.iter()):
                self.referenced_flows.add(name)

        # Sub-flows
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
                # Ignore secure properties namespace configs
                if name and not tag.tag.startswith("{http://www.mulesoft.org/schema/mule/secure-properties}"):
                    self.declared_configs.add(name)

            for attr_key, attr_val in tag.attrib.items():
                if attr_key in {"config-ref", "listener-config-ref", "request-config-ref", "context-ref"}:
                    self.referenced_configs.add(attr_val)
                    # For listener configs, track endpoints
                    if (
                        "listener" in attr_key.lower()
                        or "listener" in tag.tag.lower()
                        or tag.tag.endswith("listener")
                    ):
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

        # Exception strategies (on-error-continue/on-error-propagate)
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
        Extract references to properties, variables, and other components from text content.
        
        Args:
            text: Text content to analyze for references
        """
        if not text:
            return

        # Reserved literals to ignore
        RESERVED_WORDS = {
            "payload", "message", "attributes", "vars", "now", "null", "true", "false",
            "error", "logger", "request", "response", "dw", "as", "default", "output",
            "application", "java", "var", "if", "else", "map", "for", "while", "and", "or", "not"
        }

        # Use compiled patterns for better performance
        for pattern in self.property_patterns:
            found_keys = pattern.findall(text)
            self.yaml_property_keys_used.update(k.strip().lower() for k in found_keys)

        for pattern in self.variable_patterns:
            for match in pattern.findall(text):
                if match not in RESERVED_WORDS:
                    self.referenced_variables.add(match)

        # DataWeave CDATA blocks extraction
        dw_blocks = self.dw_block_pattern.findall(text)
        for dw in dw_blocks:
            # Extract property references from DataWeave blocks
            for pattern in self.property_patterns:
                found_keys = pattern.findall(dw)
                self.yaml_property_keys_used.update(k.strip().lower() for k in found_keys)

            # Extract variable references from DataWeave blocks
            tokens = self.token_pattern.findall(dw)
            context_reserved = {
                "output", "application", "java", "as", "var", "default", "dw",
                "true", "false", "null"
            }

            for token in tokens:
                if token in RESERVED_WORDS or token in context_reserved:
                    continue
                # Add token only if declared
                if token in self.declared_variables:
                    self.referenced_variables.add(token)

    def _scan_yaml_keys(self) -> None:
        """Scan YAML configuration files to extract property keys."""
        self.logger.info("Scanning YAML property files...")
        yaml_files = list(self.resource_dir.glob("*.yml")) + list(self.resource_dir.glob("*.yaml"))
        self.logger.info(f"Found {len(yaml_files)} YAML files to process.")
        for yml in yaml_files:
            try:
                with open(yml, 'r', encoding='utf-8') as f:
                    data = yaml.safe_load(f)
                    self._extract_yaml_keys(data)
                    self.yaml_files_processed.append(str(yml.relative_to(self.base_dir)))
            except yaml.YAMLError as e:
                msg = f"Failed to parse YAML {yml}: {e}"
                self.logger.error(msg)
                self.validation_errors.append(msg)

    def _extract_yaml_keys(self, data, prefix: str = '') -> None:
        """
        Recursively extract property keys from YAML data structure.
        
        Args:
            data: YAML data structure (dict, list, or primitive)
            prefix: Current key prefix for nested structures
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
        """Scan DataWeave (.dwl) files for script declarations and references."""
        self.logger.info("Scanning DataWeave files...")
        dwl_files = list(self.mule_dir.glob("**/*.dwl"))
        # Also scan src/main/resources/modules for DWL files
        modules_dir = self.base_dir / "src" / "main" / "resources" / "modules"
        if modules_dir.exists():
            dwl_files += list(modules_dir.glob("**/*.dwl"))
        
        self.logger.info(f"Found {len(dwl_files)} DataWeave files to process.")
        for file in dwl_files:
            try:
                # Use relative path from base_dir for consistency
                self.declared_dw_scripts.add(str(file.relative_to(self.base_dir)))
                with open(file, 'r', encoding='utf-8') as f:
                    text = f.read()
                    self._extract_references(text)
                    self.dwl_files_processed.append(str(file.relative_to(self.base_dir)))
            except Exception as e:
                msg = f"Failed to parse DWL {file}: {e}"
                self.logger.error(msg)
                self.validation_errors.append(msg)

    def _scan_additional_files(self) -> None:
        """Scan additional file types (HTML, JS) for references to Mule components."""
        text_files = list(self.base_dir.glob("**/*.html")) + list(self.base_dir.glob("**/*.js"))
        # Filter out test files
        text_files = [f for f in text_files if "src/test" not in str(f).replace("\\", "/")]
        
        self.logger.info(f"Found {len(text_files)} additional files to scan for references.")
        for file in text_files:
            try:
                with open(file, 'r', encoding='utf-8') as f:
                    text = f.read()
                    self._extract_references(text)
            except Exception as e:
                msg = f"Failed to parse {file}: {e}"
                self.logger.error(msg)
                self.validation_errors.append(msg)

    def _find_orphans(self, declared: Set[str], referenced: Set[str]) -> Tuple[List[str], List[str]]:
        """
        Compare declared and referenced components to identify orphans and used items.
        
        Args:
            declared: Set of declared component names
            referenced: Set of referenced component names
            
        Returns:
            Tuple of (orphaned_items, used_items) as sorted lists
        """
        used = sorted(list(declared & referenced))
        orphan = sorted(list(declared - referenced))
        return orphan, used

    def _generate_comprehensive_report(self) -> Dict:
        """
        Generate a comprehensive report of all orphaned and used components.
        
        Returns:
            Dictionary containing detailed analysis results
        """
        self.logger.debug(f"Declared property keys: {len(self.yaml_property_keys)}")
        self.logger.debug(f"Used property keys: {len(self.yaml_property_keys_used)}")
        
        orphan_flows_list, used_flows = self._find_orphans(
            set(self.declared_flows.keys()), 
            self.referenced_flows | self._apikit_derived_flows()
        )
        orphan_subflows_list, used_subflows = self._find_orphans(set(self.declared_subflows.keys()), self.referenced_subflows)
        orphan_configs, used_configs = self._find_orphans(self.declared_configs, self.referenced_configs)
        orphan_vars_list, used_vars = self._find_orphans(set(self.declared_variables.keys()), self.referenced_variables)
        orphan_env_vars, used_env_vars = self._find_orphans(self.declared_env_vars, self.referenced_env_vars)
        orphan_props, used_props = self._find_orphans(self.yaml_property_keys, self.yaml_property_keys_used)
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


        summary = {
            "total_orphaned_items": len(
                orphan_flows + orphan_subflows + orphan_configs + orphan_vars +
                orphan_env_vars + orphan_props + orphan_error_handlers + orphan_exc_strategies + orphan_endpoints + orphan_dw_scripts
            ),
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
                "configs": orphan_configs,
                "variables": orphan_vars,
                "env_vars": orphan_env_vars,
                "property_keys": orphan_props,
                "error_handlers": orphan_error_handlers,
                "exception_strategies": orphan_exc_strategies,
                "endpoints": orphan_endpoints,
                "dw_scripts": orphan_dw_scripts
            },
            "used": {
                "flows": used_flows_detailed,
                "subflows": used_subflows_detailed,
                "configs": used_configs,
                "variables": used_vars_detailed,
                "env_vars": used_env_vars,
                "property_keys": used_props,
                "error_handlers": used_error_handlers,
                "exception_strategies": used_exc_strategies,
                "endpoints": used_endpoints,
                "dw_scripts": used_dw_scripts
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

        return report

    def _apikit_derived_flows(self) -> Set[str]:
        """
        Identify APIKit-derived flows based on HTTP verb naming convention.
        
        Returns:
            Set of flow names that follow APIKit naming patterns
        """
        return {name for name in self.declared_flows if self.apikit_pattern.match(name)}

    def _generate_html_report(self, report: Dict, output_path: str = "orphan_report.html") -> None:
        """
        Generate an HTML report from the analysis results.
        
        Args:
            report: Dictionary containing analysis results
            output_path: Path where the HTML report should be saved
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

        def build_section(title, data: Dict[str, List], css_class: str):
            html.append(f"<h2>{title}</h2>")
            for section, items in data.items():
                html.append(f"<details><summary>{section} ({len(items)})</summary><ul>")
                for item in items:
                    if section in {"flows", "subflows"}:
                        if isinstance(item, tuple):
                            # item like (name, file_path)
                            name, file_path = item
                            html.append(f"<li><code class='{css_class}'>{name}</code> — <small>{file_path}</small></li>")
                        else:
                            # item is just string (for declared flows)
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

        html.append("</body>")
        html.append("</html>")

        with open(output_path, 'w', encoding='utf-8') as f:
            f.write('\n'.join(html))

        self.logger.info(f"HTML report generated at {output_path}")

    def generate_html_report(self, report, output_path):
        """
        Public method to generate HTML report.
        """
        self._generate_html_report(report, output_path)


def main():
    import argparse
    parser = argparse.ArgumentParser(description="MuleSoft Orphan Checker")
    parser.add_argument("project_dir", help="Path to MuleSoft project root")
    parser.add_argument("--html", help="Optional: Path to output HTML report", required=False)
    args = parser.parse_args()
    checker = MuleComprehensiveOrphanChecker(args.project_dir)
    checker.run(html_output_path=args.html)

if __name__ == "__main__":
    main()

