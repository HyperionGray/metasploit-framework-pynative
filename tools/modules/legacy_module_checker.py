#!/usr/bin/env python3
"""
Legacy Module Checker

This tool helps identify modules that should be marked as legacy based on various criteria.
"""

import os
import re
import sys
import yaml
import argparse
from datetime import datetime
from pathlib import Path
from typing import List, Dict, Tuple


class LegacyModuleChecker:
    """Analyzes Metasploit modules to identify legacy candidates"""
    
    CATEGORIES = {
        'ancient': 'Ancient Exploits (pre-2010)',
        'low_quality_fuzzer': 'Low-Quality Fuzzers',
        'redundant_enum': 'Redundant Enumeration Tools',
        'poc_only': 'Proof-of-Concept Only (Old and Unreliable)',
        'poor_integration': 'Poor Tool Integrations'
    }
    
    def __init__(self, framework_root: str):
        self.framework_root = Path(framework_root)
        self.modules_dir = self.framework_root / 'modules'
        self.legacy_db_path = self.framework_root / 'data' / 'legacy_modules.yaml'
        self.legacy_db = self._load_legacy_db()
    
    def _load_legacy_db(self) -> Dict:
        """Load the legacy modules database"""
        if self.legacy_db_path.exists():
            with open(self.legacy_db_path, 'r') as f:
                data = yaml.safe_load(f)
                if data and isinstance(data, dict):
                    return data
        return {}
    
    def find_all_modules(self, module_type: str = None) -> List[Path]:
        """Find all module files"""
        modules = []
        
        if module_type:
            search_dir = self.modules_dir / module_type
        else:
            search_dir = self.modules_dir
        
        if search_dir.exists():
            modules = list(search_dir.rglob('*.rb'))
            modules.extend(list(search_dir.rglob('*.py')))
        
        return modules
    
    def extract_disclosure_date(self, module_path: Path) -> Tuple[str, int]:
        """Extract disclosure date from module"""
        try:
            with open(module_path, 'r', encoding='utf-8', errors='ignore') as f:
                content = f.read()
            
            # Ruby format: 'DisclosureDate' => 'YYYY-MM-DD'
            match = re.search(r"'DisclosureDate'\s*=>\s*'(\d{4})-\d{2}-\d{2}'", content)
            if match:
                year = int(match.group(1))
                return match.group(1), year
            
            # Python format: 'DisclosureDate': 'YYYY-MM-DD'
            match = re.search(r"'DisclosureDate':\s*'(\d{4})-\d{2}-\d{2}'", content)
            if match:
                year = int(match.group(1))
                return match.group(1), year
            
        except Exception as e:
            pass
        
        return None, None
    
    def check_if_deprecated(self, module_path: Path) -> bool:
        """Check if module already includes Deprecated mixin"""
        try:
            with open(module_path, 'r', encoding='utf-8', errors='ignore') as f:
                content = f.read()
            
            return 'Msf::Module::Deprecated' in content
        except:
            return False
    
    def get_module_type(self, module_path: Path) -> str:
        """Determine module type from path"""
        parts = module_path.relative_to(self.modules_dir).parts
        if len(parts) > 0:
            return parts[0]
        return 'unknown'
    
    def find_ancient_exploits(self, year_cutoff: int = 2010) -> List[Dict]:
        """Find exploits with disclosure dates before cutoff year"""
        print(f"[*] Searching for exploits before {year_cutoff}...")
        
        ancient = []
        exploit_modules = self.find_all_modules('exploits')
        
        for module in exploit_modules:
            date_str, year = self.extract_disclosure_date(module)
            if year and year < year_cutoff:
                relative_path = module.relative_to(self.modules_dir)
                ancient.append({
                    'path': str(relative_path),
                    'file': module,
                    'disclosure_date': date_str,
                    'year': year
                })
        
        return sorted(ancient, key=lambda x: x['year'])
    
    def find_fuzzer_modules(self) -> List[Dict]:
        """Find all fuzzer modules"""
        print("[*] Analyzing fuzzer modules...")
        
        fuzzers = []
        fuzzer_dir = self.modules_dir / 'auxiliary' / 'fuzzers'
        
        if fuzzer_dir.exists():
            for module in fuzzer_dir.rglob('*.rb'):
                # Skip the LLVM instrumentation module - it's modern
                if 'llvm_instrumentation' in str(module):
                    continue
                
                relative_path = module.relative_to(self.modules_dir)
                fuzzers.append({
                    'path': str(relative_path).replace('.rb', ''),
                    'file': module
                })
        
        return fuzzers
    
    def find_scanner_modules(self) -> List[Dict]:
        """Find scanner/enumeration modules"""
        print("[*] Analyzing scanner modules...")
        
        scanners = []
        scanner_dir = self.modules_dir / 'auxiliary' / 'scanner'
        
        if scanner_dir.exists():
            for module in scanner_dir.rglob('*.rb'):
                relative_path = module.relative_to(self.modules_dir)
                scanners.append({
                    'path': str(relative_path).replace('.rb', ''),
                    'file': module
                })
        
        return scanners
    
    def is_marked_legacy(self, module_path: str) -> bool:
        """Check if module is in legacy database"""
        # Normalize path
        path = module_path.replace('.rb', '').replace('.py', '')
        path = path.replace('modules/', '')
        
        return path in self.legacy_db
    
    def generate_report(self, output_format: str = 'text') -> str:
        """Generate a report of legacy candidates"""
        report = []
        
        if output_format == 'text':
            report.append("=" * 80)
            report.append("LEGACY MODULE ANALYSIS REPORT")
            report.append("=" * 80)
            report.append("")
            
            # Ancient exploits
            ancient = self.find_ancient_exploits(2010)
            report.append(f"Ancient Exploits (pre-2010): {len(ancient)} found")
            report.append("-" * 80)
            
            marked = sum(1 for m in ancient if self.is_marked_legacy(m['path']))
            report.append(f"  Already marked as legacy: {marked}")
            report.append(f"  Not yet marked: {len(ancient) - marked}")
            report.append("")
            
            # Show first 10 unmarked
            unmarked = [m for m in ancient if not self.is_marked_legacy(m['path'])]
            if unmarked:
                report.append("  Sample unmarked ancient exploits:")
                for m in unmarked[:10]:
                    report.append(f"    {m['year']}: {m['path']}")
                if len(unmarked) > 10:
                    report.append(f"    ... and {len(unmarked) - 10} more")
            report.append("")
            
            # Fuzzer modules
            fuzzers = self.find_fuzzer_modules()
            report.append(f"Fuzzer Modules: {len(fuzzers)} found")
            report.append("-" * 80)
            
            marked = sum(1 for m in fuzzers if self.is_marked_legacy(m['path']))
            report.append(f"  Already marked as legacy: {marked}")
            report.append(f"  Not yet marked: {len(fuzzers) - marked}")
            
            unmarked = [m for m in fuzzers if not self.is_marked_legacy(m['path'])]
            if unmarked:
                report.append("  Unmarked fuzzers:")
                for m in unmarked:
                    report.append(f"    {m['path']}")
            report.append("")
            
            # Scanner modules
            scanners = self.find_scanner_modules()
            report.append(f"Scanner Modules: {len(scanners)} found")
            report.append("-" * 80)
            report.append("  Note: Most scanners are NOT legacy - only mark redundant ones")
            report.append("  Examples of redundant: basic port scanners, simple host discovery")
            report.append("  Keep: vulnerability-specific scanners, exploit validation, etc.")
            report.append("")
            
        elif output_format == 'csv':
            report.append("type,path,disclosure_date,is_legacy")
            
            # Ancient exploits
            for m in self.find_ancient_exploits(2010):
                is_legacy = "yes" if self.is_marked_legacy(m['path']) else "no"
                report.append(f"ancient_exploit,{m['path']},{m['disclosure_date']},{is_legacy}")
            
            # Fuzzers
            for m in self.find_fuzzer_modules():
                is_legacy = "yes" if self.is_marked_legacy(m['path']) else "no"
                report.append(f"fuzzer,{m['path']},N/A,{is_legacy}")
        
        return "\n".join(report)
    
    def suggest_alternatives(self, module_type: str) -> str:
        """Suggest alternatives for different module types"""
        alternatives = {
            'fuzzer': """
Recommended Modern Fuzzing Tools:
- AFL++ (https://aflplus.plus/) - Coverage-guided fuzzing
- libFuzzer (part of LLVM) - In-process fuzzing
- Honggfuzz (https://honggfuzz.dev/) - Security-oriented fuzzer
- boofuzz (https://github.com/jtpereyda/boofuzz) - Protocol fuzzer

For web applications:
- ffuf (https://github.com/ffuf/ffuf) - Fast web fuzzer
- wfuzz (https://github.com/xmendez/wfuzz) - Web application fuzzer

For this project, use:
- modules/auxiliary/fuzzers/binary/llvm_instrumentation.rb
- Integrated AFL++/libFuzzer support with sanitizers
""",
            'scanner': """
Recommended Enumeration Tools:
- nmap (https://nmap.org/) - Network scanner
- masscan (https://github.com/robertdavidgraham/masscan) - Fast port scanner
- rustscan (https://github.com/RustScan/RustScan) - Modern port scanner

Keep Metasploit scanners that:
- Validate specific vulnerabilities
- Perform complex exploit checks
- Are part of exploit workflows
""",
        }
        
        return alternatives.get(module_type, "No specific alternatives defined")


def main():
    parser = argparse.ArgumentParser(
        description='Identify and analyze legacy Metasploit modules',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  # Generate full report
  python legacy_module_checker.py

  # Find ancient exploits
  python legacy_module_checker.py --ancient 2010

  # Show fuzzer analysis
  python legacy_module_checker.py --fuzzers

  # Export to CSV
  python legacy_module_checker.py --format csv > legacy_report.csv
        """
    )
    
    parser.add_argument(
        '--root',
        default='.',
        help='Metasploit framework root directory (default: current directory)'
    )
    
    parser.add_argument(
        '--ancient',
        type=int,
        metavar='YEAR',
        help='Find exploits before this year (default: 2010)'
    )
    
    parser.add_argument(
        '--fuzzers',
        action='store_true',
        help='Show fuzzer module analysis'
    )
    
    parser.add_argument(
        '--scanners',
        action='store_true',
        help='Show scanner module analysis'
    )
    
    parser.add_argument(
        '--format',
        choices=['text', 'csv'],
        default='text',
        help='Output format (default: text)'
    )
    
    parser.add_argument(
        '--alternatives',
        choices=['fuzzer', 'scanner'],
        help='Show recommended alternatives for module type'
    )
    
    args = parser.parse_args()
    
    # Determine framework root
    framework_root = os.path.abspath(args.root)
    if not os.path.exists(os.path.join(framework_root, 'modules')):
        print(f"Error: {framework_root} doesn't appear to be a Metasploit framework root")
        print("(modules directory not found)")
        sys.exit(1)
    
    checker = LegacyModuleChecker(framework_root)
    
    # Show alternatives if requested
    if args.alternatives:
        print(checker.suggest_alternatives(args.alternatives))
        return
    
    # Handle specific analysis requests
    if args.ancient:
        ancient = checker.find_ancient_exploits(args.ancient)
        print(f"Found {len(ancient)} exploits before {args.ancient}")
        for m in ancient[:20]:  # Show first 20
            legacy_marker = " [LEGACY]" if checker.is_marked_legacy(m['path']) else ""
            print(f"  {m['year']}: {m['path']}{legacy_marker}")
        if len(ancient) > 20:
            print(f"  ... and {len(ancient) - 20} more")
        return
    
    if args.fuzzers:
        fuzzers = checker.find_fuzzer_modules()
        print(f"Found {len(fuzzers)} fuzzer modules")
        for m in fuzzers:
            legacy_marker = " [LEGACY]" if checker.is_marked_legacy(m['path']) else ""
            print(f"  {m['path']}{legacy_marker}")
        print("\nRecommendation: Most simple fuzzers should be marked as legacy.")
        print("Use modern fuzzers like AFL++, libFuzzer, or Honggfuzz instead.")
        return
    
    if args.scanners:
        scanners = checker.find_scanner_modules()
        print(f"Found {len(scanners)} scanner modules")
        print("Note: Review each scanner individually. Many provide unique value.")
        print("Mark as legacy only if completely redundant with nmap/masscan.")
        return
    
    # Default: generate full report
    report = checker.generate_report(args.format)
    print(report)


if __name__ == '__main__':
    main()
