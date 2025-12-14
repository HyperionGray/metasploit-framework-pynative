#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
Legacy Module Migrator

This tool helps identify and categorize Metasploit modules based on disclosure date,
preparing them for migration to the modules_legacy/ directory as part of the
Python-native conversion effort (Round 4).
"""

import os
import re
import sys
import argparse
from datetime import datetime
from pathlib import Path
from typing import List, Dict, Tuple, Optional


class ModuleInfo:
    """Container for module metadata."""
    
    def __init__(self, path: str):
        self.path = path
        self.relative_path = None
        self.disclosure_date = None
        self.name = None
        self.rank = None
        self.module_type = None
        self.description = None
        self.is_legacy = False
        
    def __repr__(self):
        return f"ModuleInfo({self.relative_path}, {self.disclosure_date})"


class LegacyModuleMigrator:
    """Analyzes and categorizes Metasploit modules for legacy migration."""
    
    # Date threshold for legacy classification
    LEGACY_CUTOFF = datetime(2020, 1, 1)
    
    def __init__(self, framework_root: str):
        """
        Initialize migrator.
        
        Args:
            framework_root: Path to Metasploit Framework root directory
        """
        self.framework_root = Path(framework_root)
        self.modules_dir = self.framework_root / 'modules'
        self.legacy_dir = self.framework_root / 'modules_legacy'
        
        self.modules: List[ModuleInfo] = []
        self.stats = {
            'total': 0,
            'legacy': 0,
            'current': 0,
            'no_date': 0,
            'by_type': {},
            'by_year': {}
        }
    
    def parse_disclosure_date(self, content: str) -> Optional[datetime]:
        """
        Extract disclosure date from module content.
        
        Args:
            content: Module file content
            
        Returns:
            Parsed date or None
        """
        # Match Ruby date format: 'DisclosureDate' => '2020-01-15'
        pattern = r"['\"]DisclosureDate['\"]\s*=>\s*['\"](\d{4}-\d{2}-\d{2})['\"]"
        match = re.search(pattern, content)
        
        if match:
            try:
                date_str = match.group(1)
                return datetime.strptime(date_str, '%Y-%m-%d')
            except ValueError:
                return None
        
        return None
    
    def parse_module_name(self, content: str) -> Optional[str]:
        """
        Extract module name from content.
        
        Args:
            content: Module file content
            
        Returns:
            Module name or None
        """
        pattern = r"['\"]Name['\"]\s*=>\s*['\"]([^'\"]+)['\"]"
        match = re.search(pattern, content)
        return match.group(1) if match else None
    
    def parse_module_rank(self, content: str) -> Optional[str]:
        """
        Extract module rank from content.
        
        Args:
            content: Module file content
            
        Returns:
            Module rank or None
        """
        pattern = r"Rank\s*=\s*(\w+Ranking)"
        match = re.search(pattern, content)
        return match.group(1) if match else None
    
    def analyze_module(self, module_path: Path) -> ModuleInfo:
        """
        Analyze a single module file.
        
        Args:
            module_path: Path to module file
            
        Returns:
            ModuleInfo object
        """
        info = ModuleInfo(str(module_path))
        info.relative_path = str(module_path.relative_to(self.modules_dir))
        
        # Determine module type from path
        parts = info.relative_path.split(os.sep)
        if len(parts) > 0:
            info.module_type = parts[0]
        
        try:
            with open(module_path, 'r', encoding='utf-8', errors='ignore') as f:
                content = f.read()
                
                info.disclosure_date = self.parse_disclosure_date(content)
                info.name = self.parse_module_name(content)
                info.rank = self.parse_module_rank(content)
                
                # Determine if legacy
                if info.disclosure_date:
                    info.is_legacy = info.disclosure_date < self.LEGACY_CUTOFF
                    
        except Exception as e:
            print(f"Error analyzing {module_path}: {e}", file=sys.stderr)
        
        return info
    
    def scan_modules(self, module_type: Optional[str] = None) -> None:
        """
        Scan all modules in the modules directory.
        
        Args:
            module_type: Specific type to scan (exploits, auxiliary, etc.) or None for all
        """
        print(f"Scanning modules in {self.modules_dir}...")
        
        # Determine which directories to scan
        if module_type:
            scan_dirs = [self.modules_dir / module_type]
        else:
            scan_dirs = [
                self.modules_dir / 'exploits',
                self.modules_dir / 'auxiliary',
                self.modules_dir / 'post',
                self.modules_dir / 'payloads',
                self.modules_dir / 'encoders',
                self.modules_dir / 'evasion',
                self.modules_dir / 'nops'
            ]
        
        # Scan each directory
        for scan_dir in scan_dirs:
            if not scan_dir.exists():
                continue
                
            print(f"  Scanning {scan_dir.name}/...")
            
            # Find all .rb files
            for module_path in scan_dir.rglob('*.rb'):
                info = self.analyze_module(module_path)
                self.modules.append(info)
                
                # Update statistics
                self.stats['total'] += 1
                
                if info.disclosure_date:
                    if info.is_legacy:
                        self.stats['legacy'] += 1
                    else:
                        self.stats['current'] += 1
                    
                    # Count by year
                    year = info.disclosure_date.year
                    self.stats['by_year'][year] = self.stats['by_year'].get(year, 0) + 1
                else:
                    self.stats['no_date'] += 1
                
                # Count by type
                if info.module_type:
                    self.stats['by_type'][info.module_type] = \
                        self.stats['by_type'].get(info.module_type, 0) + 1
        
        print(f"Scanned {self.stats['total']} modules")
    
    def print_statistics(self) -> None:
        """Print analysis statistics."""
        print("\n" + "="*60)
        print("MODULE ANALYSIS STATISTICS")
        print("="*60)
        
        print(f"\nTotal modules: {self.stats['total']}")
        print(f"  Legacy (pre-2020): {self.stats['legacy']}")
        print(f"  Current (2020+): {self.stats['current']}")
        print(f"  No date: {self.stats['no_date']}")
        
        print("\nModules by Type:")
        for mtype, count in sorted(self.stats['by_type'].items()):
            print(f"  {mtype:15s}: {count:4d}")
        
        print("\nModules by Year:")
        for year in sorted(self.stats['by_year'].keys()):
            count = self.stats['by_year'][year]
            is_legacy = year < 2020
            marker = "LEGACY" if is_legacy else "CURRENT"
            print(f"  {year}: {count:4d} [{marker}]")
    
    def list_legacy_modules(self, limit: int = 50) -> None:
        """
        List legacy modules.
        
        Args:
            limit: Maximum number to display
        """
        legacy_modules = [m for m in self.modules if m.is_legacy]
        
        print(f"\n{'='*60}")
        print(f"LEGACY MODULES (Pre-2020) - Showing {min(limit, len(legacy_modules))} of {len(legacy_modules)}")
        print('='*60)
        
        for i, module in enumerate(sorted(legacy_modules, key=lambda m: m.disclosure_date or datetime.min)[:limit]):
            date_str = module.disclosure_date.strftime('%Y-%m-%d') if module.disclosure_date else 'UNKNOWN'
            print(f"{i+1:3d}. [{date_str}] {module.relative_path}")
            if module.name:
                print(f"     {module.name}")
    
    def list_current_modules(self, limit: int = 50) -> None:
        """
        List current (post-2020) modules.
        
        Args:
            limit: Maximum number to display
        """
        current_modules = [m for m in self.modules if not m.is_legacy and m.disclosure_date]
        
        print(f"\n{'='*60}")
        print(f"CURRENT MODULES (2020+) - Showing {min(limit, len(current_modules))} of {len(current_modules)}")
        print('='*60)
        
        for i, module in enumerate(sorted(current_modules, key=lambda m: m.disclosure_date, reverse=True)[:limit]):
            date_str = module.disclosure_date.strftime('%Y-%m-%d')
            print(f"{i+1:3d}. [{date_str}] {module.relative_path}")
            if module.name:
                print(f"     {module.name}")
    
    def generate_migration_script(self, output_file: str) -> None:
        """
        Generate bash script to move legacy modules.
        
        Args:
            output_file: Path to output script file
        """
        legacy_modules = [m for m in self.modules if m.is_legacy]
        
        print(f"\nGenerating migration script: {output_file}")
        
        with open(output_file, 'w') as f:
            f.write("#!/bin/bash\n")
            f.write("# Auto-generated legacy module migration script\n")
            f.write(f"# Generated: {datetime.now().isoformat()}\n")
            f.write(f"# Total modules to migrate: {len(legacy_modules)}\n\n")
            
            f.write("set -e\n\n")
            f.write(f'FRAMEWORK_ROOT="{self.framework_root}"\n')
            f.write('MODULES_DIR="$FRAMEWORK_ROOT/modules"\n')
            f.write('LEGACY_DIR="$FRAMEWORK_ROOT/modules_legacy"\n\n')
            
            f.write("echo 'Creating legacy directory structure...'\n")
            f.write('mkdir -p "$LEGACY_DIR"/{exploits,auxiliary,post,payloads,encoders,evasion,nops}\n\n')
            
            f.write(f"echo 'Migrating {len(legacy_modules)} legacy modules...'\n\n")
            
            for module in legacy_modules:
                src = f"$MODULES_DIR/{module.relative_path}"
                dst = f"$LEGACY_DIR/{module.relative_path}"
                # Get directory from relative path, not the shell variable version
                dst_dir = os.path.dirname(module.relative_path)
                dst_dir_full = f"$LEGACY_DIR/{dst_dir}" if dst_dir else "$LEGACY_DIR"
                
                f.write(f"# {module.name or module.relative_path}\n")
                f.write(f"mkdir -p {dst_dir_full}\n")
                f.write(f"mv {src} {dst}\n\n")
            
            f.write('echo "Migration complete!"\n')
            f.write(f'echo "Moved {len(legacy_modules)} modules to modules_legacy/"\n')
        
        # Make script executable
        os.chmod(output_file, 0o755)
        print(f"  Script created with {len(legacy_modules)} module moves")


def main():
    """Main entry point."""
    parser = argparse.ArgumentParser(
        description='Identify and migrate legacy Metasploit modules (pre-2020)',
        formatter_class=argparse.RawDescriptionHelpFormatter
    )
    
    parser.add_argument(
        '-d', '--directory',
        default='.',
        help='Metasploit Framework root directory (default: current directory)'
    )
    
    parser.add_argument(
        '-t', '--type',
        choices=['exploits', 'auxiliary', 'post', 'payloads', 'encoders', 'evasion', 'nops'],
        help='Specific module type to analyze'
    )
    
    parser.add_argument(
        '-l', '--list-legacy',
        action='store_true',
        help='List legacy modules (pre-2020)'
    )
    
    parser.add_argument(
        '-c', '--list-current',
        action='store_true',
        help='List current modules (2020+)'
    )
    
    parser.add_argument(
        '-s', '--stats',
        action='store_true',
        help='Show statistics only'
    )
    
    parser.add_argument(
        '-g', '--generate-script',
        metavar='FILE',
        help='Generate migration bash script'
    )
    
    parser.add_argument(
        '-n', '--limit',
        type=int,
        default=50,
        help='Limit number of modules to display (default: 50)'
    )
    
    args = parser.parse_args()
    
    # Initialize migrator
    migrator = LegacyModuleMigrator(args.directory)
    
    # Scan modules
    migrator.scan_modules(args.type)
    
    # Show statistics
    if args.stats or not (args.list_legacy or args.list_current or args.generate_script):
        migrator.print_statistics()
    
    # List legacy modules
    if args.list_legacy:
        migrator.list_legacy_modules(args.limit)
    
    # List current modules
    if args.list_current:
        migrator.list_current_modules(args.limit)
    
    # Generate migration script
    if args.generate_script:
        migrator.generate_migration_script(args.generate_script)


if __name__ == '__main__':
    main()
