#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
Ruby to Python Module Converter

Assists in converting Ruby Metasploit modules to Python by performing
common pattern transformations and generating a Python template.
"""

import re
import sys
import argparse
from pathlib import Path
from typing import Dict, Optional, List


class RubyToPythonConverter:
    """Converts Ruby Metasploit modules to Python equivalents."""
    
    # Common Ruby to Python pattern mappings
    PATTERNS = [
        # String interpolation
        (r'#\{([^}]+)\}', r'{\1}'),  # #{var} -> {var}
        
        # Symbols to strings
        (r':(\w+)', r"'\1'"),  # :symbol -> 'symbol'
        
        # Class syntax
        (r'class (\w+) < ([\w:]+)', r'class \1(\2):'),
        
        # Method definitions
        (r'def (\w+)\(([^)]*)\)', r'def \1(\2):'),
        (r'def (\w+)$', r'def \1():'),
        
        # Boolean values
        (r'\btrue\b', 'True'),
        (r'\bfalse\b', 'False'),
        (r'\bnil\b', 'None'),
        
        # Hash rockets
        (r'=>', ':'),
        
        # String concatenation
        (r'\s\+\s', ' + '),
        
        # Comments
        (r'^\s*#([^!])', r'#\1'),
        
        # Block syntax (simple cases)
        (r'\.each\s+do\s+\|([^|]+)\|', r'for \1 in '),
        (r'\.each\s+\{([^}]+)\}', r'for ... in ...:'),
        
        # Control flow
        (r'\bunless\b', 'if not'),
        (r'\belsif\b', 'elif'),
        
        # String methods (Note: Manual conversion needed for len())
        # (r'\.length', 'len()'),  # Needs context: obj.length -> len(obj)
        # (r'\.size', 'len()'),    # Needs context: obj.size -> len(obj)
        (r'\.empty\?', ' == \'\''),
        
        # Print statements
        (r'puts\s+', 'print('),
        (r'print_status\s+', 'logging.info('),
        (r'print_good\s+', 'logging.info('),
        (r'print_error\s+', 'logging.error('),
        (r'print_warning\s+', 'logging.warning('),
    ]
    
    def __init__(self, ruby_file: str):
        """
        Initialize converter.
        
        Args:
            ruby_file: Path to Ruby module file
        """
        self.ruby_file = Path(ruby_file)
        self.ruby_content = ''
        self.metadata = {}
        
        if not self.ruby_file.exists():
            raise FileNotFoundError(f"File not found: {ruby_file}")
        
        with open(self.ruby_file, 'r', encoding='utf-8', errors='ignore') as f:
            self.ruby_content = f.read()
    
    def extract_metadata(self) -> Dict[str, any]:
        """
        Extract module metadata from Ruby code.
        
        Returns:
            Dictionary of metadata fields
        """
        metadata = {}
        
        # Extract name
        match = re.search(r"'Name'\s*=>\s*'([^']+)'", self.ruby_content)
        if match:
            metadata['name'] = match.group(1)
        
        # Extract description
        match = re.search(r"'Description'\s*=>\s*%q\{([^}]+)\}", self.ruby_content, re.DOTALL)
        if not match:
            match = re.search(r'"Description"\s*=>\s*%q\{([^}]+)\}', self.ruby_content, re.DOTALL)
        if match:
            desc = match.group(1).strip()
            metadata['description'] = desc
        
        # Extract authors
        authors = []
        match = re.search(r"'Author'\s*=>\s*\[(.*?)\]", self.ruby_content, re.DOTALL)
        if match:
            author_block = match.group(1)
            for author_match in re.finditer(r"'([^']+)'", author_block):
                authors.append(author_match.group(1))
        metadata['authors'] = authors
        
        # Extract references
        references = []
        match = re.search(r"'References'\s*=>\s*\[(.*?)\]", self.ruby_content, re.DOTALL)
        if match:
            ref_block = match.group(1)
            # Extract CVEs
            for cve_match in re.finditer(r"\['CVE',\s*'([^']+)'\]", ref_block):
                references.append(('cve', cve_match.group(1)))
            # Extract URLs
            for url_match in re.finditer(r"\['URL',\s*'([^']+)'\]", ref_block):
                references.append(('url', url_match.group(1)))
        metadata['references'] = references
        
        # Extract disclosure date
        match = re.search(r"'DisclosureDate'\s*=>\s*'([^']+)'", self.ruby_content)
        if match:
            metadata['disclosure_date'] = match.group(1)
        
        # Extract platform
        match = re.search(r"'Platform'\s*=>\s*(['\"]\w+['\"]|\[.*?\])", self.ruby_content)
        if match:
            platform_str = match.group(1)
            metadata['platform'] = platform_str
        
        # Extract targets
        targets = []
        match = re.search(r"'Targets'\s*=>\s*\[(.*?)\]", self.ruby_content, re.DOTALL)
        if match:
            target_block = match.group(1)
            # Simple target extraction
            for target_match in re.finditer(r"\[\s*'([^']+)'", target_block):
                targets.append(target_match.group(1))
        metadata['targets'] = targets
        
        # Extract license
        match = re.search(r"'License'\s*=>\s*(\w+)", self.ruby_content)
        if match:
            metadata['license'] = match.group(1)
        
        # Extract rank
        match = re.search(r"Rank\s*=\s*(\w+)", self.ruby_content)
        if match:
            metadata['rank'] = match.group(1)
        
        self.metadata = metadata
        return metadata
    
    def generate_python_template(self) -> str:
        """
        Generate Python module template from extracted metadata.
        
        Returns:
            Python module code as string
        """
        self.extract_metadata()
        
        # Build Python module
        lines = []
        
        # Header
        lines.append("#!/usr/bin/env python3")
        lines.append("# -*- coding: utf-8 -*-")
        lines.append("")
        lines.append('"""')
        if self.metadata.get('name'):
            lines.append(f"{self.metadata['name']}")
            lines.append("")
        if self.metadata.get('description'):
            desc = self.metadata['description']
            for line in desc.split('\n'):
                lines.append(line.strip())
        lines.append('"""')
        lines.append("")
        
        # Imports
        lines.append("import logging")
        lines.append("import sys")
        lines.append("import os")
        lines.append("")
        lines.append("# Add lib path")
        lines.append("sys.path.insert(0, os.path.join(os.path.dirname(__file__), '../../../../lib'))")
        lines.append("")
        lines.append("from metasploit import module")
        lines.append("from msf.http_client import HTTPClient, CheckCode")
        lines.append("")
        
        # Metadata dictionary
        lines.append("metadata = {")
        
        if self.metadata.get('name'):
            lines.append(f"    'name': '{self.metadata['name']}',")
        
        if self.metadata.get('description'):
            lines.append("    'description': '''")
            desc = self.metadata['description']
            for line in desc.split('\n'):
                lines.append(f"        {line.strip()}")
            lines.append("    ''',")
        
        if self.metadata.get('authors'):
            lines.append("    'authors': [")
            for author in self.metadata['authors']:
                lines.append(f"        '{author}',")
            lines.append("    ],")
        
        if self.metadata.get('disclosure_date'):
            lines.append(f"    'date': '{self.metadata['disclosure_date']}',")
        
        if self.metadata.get('license'):
            license_val = self.metadata['license']
            if not license_val.startswith("'") and not license_val.startswith('"'):
                license_val = f"'{license_val}'"
            lines.append(f"    'license': {license_val},")
        
        if self.metadata.get('references'):
            lines.append("    'references': [")
            for ref_type, ref_val in self.metadata['references']:
                lines.append(f"        {{'type': '{ref_type}', 'ref': '{ref_val}'}},")
            lines.append("    ],")
        
        lines.append("    'type': 'remote_exploit',  # TODO: Adjust type")
        
        if self.metadata.get('targets'):
            lines.append("    'targets': [")
            for target in self.metadata['targets']:
                lines.append(f"        {{'name': '{target}'}},  # TODO: Add platform/arch")
            lines.append("    ],")
        
        lines.append("    'options': {")
        lines.append("        'rhost': {'type': 'address', 'description': 'Target address', 'required': True},")
        lines.append("        'rport': {'type': 'port', 'description': 'Target port', 'required': True, 'default': 80},")
        lines.append("        # TODO: Add module-specific options")
        lines.append("    },")
        lines.append("    'notes': {")
        lines.append("        'stability': ['CRASH_SAFE'],  # TODO: Adjust")
        lines.append("        'reliability': ['REPEATABLE_SESSION'],  # TODO: Adjust")
        lines.append("        'side_effects': ['IOC_IN_LOGS']  # TODO: Adjust")
        lines.append("    }")
        lines.append("}")
        lines.append("")
        
        # Run function
        lines.append("")
        lines.append("def run(args):")
        lines.append("    '''Module entry point.'''")
        lines.append("    module.LogHandler.setup(msg_prefix=f\"{args['rhost']}:{args['rport']} - \")")
        lines.append("    ")
        lines.append("    rhost = args['rhost']")
        lines.append("    rport = args['rport']")
        lines.append("    ")
        lines.append("    logging.info('Starting module execution...')")
        lines.append("    ")
        lines.append("    # TODO: Implement module logic")
        lines.append("    # 1. Create HTTP client or TCP socket")
        lines.append("    # 2. Check if target is vulnerable")
        lines.append("    # 3. Exploit the vulnerability")
        lines.append("    # 4. Handle success/failure")
        lines.append("    ")
        lines.append("    try:")
        lines.append("        client = HTTPClient(rhost=rhost, rport=rport)")
        lines.append("        ")
        lines.append("        # Your exploit code here")
        lines.append("        response = client.get('/')")
        lines.append("        if response:")
        lines.append("            logging.info(f'Response status: {response.status_code}')")
        lines.append("        ")
        lines.append("        client.close()")
        lines.append("        ")
        lines.append("    except Exception as e:")
        lines.append("        logging.error(f'Exploitation failed: {e}')")
        lines.append("        return")
        lines.append("    ")
        lines.append("    logging.info('Module execution complete')")
        lines.append("")
        
        # Main
        lines.append("")
        lines.append("if __name__ == '__main__':")
        lines.append("    module.run(metadata, run)")
        lines.append("")
        
        return '\n'.join(lines)
    
    def save_python_module(self, output_file: str) -> None:
        """
        Save generated Python module to file.
        
        Args:
            output_file: Path to output Python file
        """
        python_code = self.generate_python_template()
        
        with open(output_file, 'w') as f:
            f.write(python_code)
        
        print(f"Generated Python module: {output_file}")
        print(f"  Name: {self.metadata.get('name', 'N/A')}")
        print(f"  Date: {self.metadata.get('disclosure_date', 'N/A')}")
        print(f"  Authors: {len(self.metadata.get('authors', []))}")
        print(f"  References: {len(self.metadata.get('references', []))}")
        print()
        print("TODO: Manual conversion steps required:")
        print("  1. Implement check() function for vulnerability detection")
        print("  2. Implement exploit() function with actual exploit logic")
        print("  3. Convert Ruby-specific code (pack/unpack, regex, etc.)")
        print("  4. Add proper error handling")
        print("  5. Test module thoroughly")


def main():
    """Main entry point."""
    parser = argparse.ArgumentParser(
        description='Convert Ruby Metasploit modules to Python templates',
        formatter_class=argparse.RawDescriptionHelpFormatter
    )
    
    parser.add_argument(
        'input_file',
        help='Ruby module file to convert (.rb)'
    )
    
    parser.add_argument(
        '-o', '--output',
        help='Output Python file (.py). Default: same name with .py extension'
    )
    
    args = parser.parse_args()
    
    # Determine output filename
    if args.output:
        output_file = args.output
    else:
        output_file = str(Path(args.input_file).with_suffix('.py'))
    
    # Convert module
    try:
        converter = RubyToPythonConverter(args.input_file)
        converter.save_python_module(output_file)
    except Exception as e:
        print(f"Error: {e}", file=sys.stderr)
        sys.exit(1)


if __name__ == '__main__':
    main()
