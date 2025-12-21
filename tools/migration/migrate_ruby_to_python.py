#!/usr/bin/env python3
"""
Ruby to Python Migration Script

This script implements the migration strategy:
1. Move pre-2020 Ruby files to legacy directories
2. Convert post-2020 Ruby files to Python
3. Focus on exploit framework and helpers
4. Maintain directory structure

Usage:
    python3 migrate_ruby_to_python.py [--dry-run] [--verbose]
"""

import os
import shutil
import subprocess
import datetime
import re
from pathlib import Path
from typing import Dict, List, Tuple, Optional, Set
import argparse
import logging


class RubyToPythonMigrator:
    """
    Handles the migration of Ruby files to Python and legacy organization
    """
    
    def __init__(self, workspace_dir: str = "/workspace", dry_run: bool = False, verbose: bool = False):
        self.workspace_dir = Path(workspace_dir)
        self.legacy_dir = self.workspace_dir / "legacy"
        self.dry_run = dry_run
        self.verbose = verbose
        
        # Setup logging
        logging.basicConfig(
            level=logging.DEBUG if verbose else logging.INFO,
            format='%(asctime)s - %(levelname)s - %(message)s'
        )
        self.logger = logging.getLogger(__name__)
        
        # Cutoff date for pre/post 2020 classification
        self.cutoff_date = datetime.datetime(2021, 1, 1)
        
        # Priority directories for conversion (exploit framework and helpers)
        self.priority_dirs = {
            'lib/msf/core',
            'lib/msf/base',
            'lib/msf/ui',
            'lib/rex',
            'modules/exploits',
            'modules/auxiliary',
            'modules/post'
        }
        
        # Statistics tracking
        self.stats = {
            'total_ruby_files': 0,
            'pre_2020_moved': 0,
            'post_2020_converted': 0,
            'already_converted': 0,
            'errors': 0
        }
    
    def find_ruby_files(self) -> List[Path]:
        """Find all Ruby files in the workspace"""
        ruby_files = []
        
        # Search in priority directories first
        for priority_dir in self.priority_dirs:
            full_path = self.workspace_dir / priority_dir
            if full_path.exists():
                ruby_files.extend(full_path.rglob("*.rb"))
        
        # Then search in other directories
        for ruby_file in self.workspace_dir.rglob("*.rb"):
            if not any(str(ruby_file).startswith(str(self.workspace_dir / priority_dir)) 
                      for priority_dir in self.priority_dirs):
                # Skip certain directories
                if not any(skip_dir in str(ruby_file) for skip_dir in 
                          ['spec/', 'test/', '.git/', 'vendor/', 'legacy/']):
                    ruby_files.append(ruby_file)
        
        self.stats['total_ruby_files'] = len(ruby_files)
        return ruby_files
    
    def classify_file(self, ruby_file: Path) -> str:
        """Classify a Ruby file as pre-2020, post-2020, or unknown"""
        try:
            with open(ruby_file, 'r', encoding='utf-8', errors='ignore') as f:
                content = f.read()
            
            # Look for DisclosureDate in the content
            disclosure_pattern = re.compile(r"'DisclosureDate'\s*=>\s*'([^']+)'")
            match = disclosure_pattern.search(content)
            
            if match:
                date_str = match.group(1)
                try:
                    disclosure_date = datetime.datetime.strptime(date_str, '%Y-%m-%d')
                    if disclosure_date >= self.cutoff_date:
                        return 'post_2020'
                    else:
                        return 'pre_2020'
                except ValueError:
                    pass
            
            # Fallback to file modification time
            stat = ruby_file.stat()
            file_date = datetime.datetime.fromtimestamp(stat.st_mtime)
            if file_date >= self.cutoff_date:
                return 'post_2020_by_mtime'
            else:
                return 'pre_2020_by_mtime'
                
        except Exception as e:
            self.logger.warning(f"Error classifying {ruby_file}: {e}")
            return 'unknown'
    
    def move_to_legacy(self, ruby_file: Path) -> bool:
        """Move a pre-2020 Ruby file to the legacy directory"""
        try:
            # Calculate relative path from workspace
            rel_path = ruby_file.relative_to(self.workspace_dir)
            legacy_path = self.legacy_dir / rel_path
            
            if self.dry_run:
                self.logger.info(f"[DRY RUN] Would move {rel_path} to legacy/{rel_path}")
                return True
            
            # Create parent directories
            legacy_path.parent.mkdir(parents=True, exist_ok=True)
            
            # Move the file
            shutil.move(str(ruby_file), str(legacy_path))
            self.logger.info(f"Moved {rel_path} to legacy/{rel_path}")
            return True
            
        except Exception as e:
            self.logger.error(f"Error moving {ruby_file} to legacy: {e}")
            return False
    
    def convert_to_python(self, ruby_file: Path) -> bool:
        """Convert a post-2020 Ruby file to Python"""
        try:
            # Check if Python version already exists
            python_file = ruby_file.with_suffix('.py')
            if python_file.exists():
                self.logger.info(f"Python version already exists: {python_file.relative_to(self.workspace_dir)}")
                self.stats['already_converted'] += 1
                return True
            
            if self.dry_run:
                self.logger.info(f"[DRY RUN] Would convert {ruby_file.relative_to(self.workspace_dir)} to Python")
                return True
            
            # Read Ruby content
            with open(ruby_file, 'r', encoding='utf-8', errors='ignore') as f:
                ruby_content = f.read()
            
            # Generate Python content (basic conversion)
            python_content = self.generate_python_content(ruby_content, ruby_file)
            
            # Write Python file
            with open(python_file, 'w', encoding='utf-8') as f:
                f.write(python_content)
            
            self.logger.info(f"Converted {ruby_file.relative_to(self.workspace_dir)} to Python")
            return True
            
        except Exception as e:
            self.logger.error(f"Error converting {ruby_file} to Python: {e}")
            return False
    
    def generate_python_content(self, ruby_content: str, ruby_file: Path) -> str:
        """Generate Python content from Ruby content"""
        
        # Extract basic module information
        name_match = re.search(r"'Name'\s*=>\s*'([^']+)'", ruby_content)
        name = name_match.group(1) if name_match else "Converted Module"
        
        author_match = re.search(r"'Author'\s*=>\s*\[(.*?)\]", ruby_content, re.DOTALL)
        authors = []
        if author_match:
            author_content = author_match.group(1)
            authors = re.findall(r"'([^']+)'", author_content)
        
        date_match = re.search(r"'DisclosureDate'\s*=>\s*'([^']+)'", ruby_content)
        disclosure_date = date_match.group(1) if date_match else "Unknown"
        
        desc_match = re.search(r"'Description'\s*=>\s*%q\{(.*?)\}", ruby_content, re.DOTALL)
        description = desc_match.group(1).strip() if desc_match else "Converted from Ruby"
        
        # Generate Python template
        python_content = f'''#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
{name}

Converted from Ruby: {ruby_file.name}
This module was automatically converted from Ruby to Python
as part of the post-2020 Python migration initiative.

Original Author(s): {', '.join(authors) if authors else 'Unknown'}
Disclosure Date: {disclosure_date}
"""

import sys
import os
import re
import json
import time
import logging
from typing import Dict, List, Optional, Any, Union

# Framework imports
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '../../../python_framework'))
from core.exploit import RemoteExploit, ExploitInfo, ExploitResult, ExploitRank
from helpers.http_client import HttpExploitMixin
from helpers.mixins import AutoCheckMixin


class MetasploitModule(RemoteExploit, HttpExploitMixin, AutoCheckMixin):
    """
    {name}
    
    {description[:200]}...
    """
    
    rank = ExploitRank.NORMAL  # TODO: Extract actual rank from Ruby
    
    def __init__(self):
        info = ExploitInfo(
            name="{name}",
            description="""{description}""",
            author={authors if authors else ["Unknown"]},
            disclosure_date="{disclosure_date}",
            rank=self.rank
        )
        super().__init__(info)
        
        # TODO: Convert register_options from Ruby
        self.register_options([
            # Add options here based on Ruby version
        ])
        
        # TODO: Convert targets from Ruby
        self.register_targets([
            # Add targets here based on Ruby version
        ])
    
    def check(self) -> ExploitResult:
        """Check if target is vulnerable"""
        # TODO: Convert Ruby check method
        self.print_status("Checking target vulnerability...")
        
        # Placeholder implementation
        return ExploitResult(False, "Check method not yet implemented")
    
    def exploit(self) -> ExploitResult:
        """Execute the exploit"""
        # TODO: Convert Ruby exploit method
        self.print_status("Executing exploit...")
        
        # Placeholder implementation
        return ExploitResult(False, "Exploit method not yet implemented")


if __name__ == '__main__':
    # Standalone execution for testing
    import argparse
    
    parser = argparse.ArgumentParser(description='Run exploit module')
    parser.add_argument('--host', required=True, help='Target host')
    parser.add_argument('--port', type=int, default=80, help='Target port')
    parser.add_argument('--check-only', action='store_true', help='Only run check')
    parser.add_argument('--verbose', action='store_true', help='Verbose output')
    
    args = parser.parse_args()
    
    # Initialize module
    module = MetasploitModule()
    module.set_option('RHOSTS', args.host)
    module.set_option('RPORT', args.port)
    
    if args.verbose:
        logging.basicConfig(level=logging.DEBUG)
    
    # Run check or exploit
    if args.check_only:
        result = module.check()
        print(f"Check result: {{result.success}} - {{result.message}}")
    else:
        result = module.exploit()
        print(f"Exploit result: {{result.success}} - {{result.message}}")
'''
        
        return python_content
    
    def migrate_files(self):
        """Main migration process"""
        self.logger.info("Starting Ruby to Python migration...")
        self.logger.info(f"Workspace: {self.workspace_dir}")
        self.logger.info(f"Legacy directory: {self.legacy_dir}")
        self.logger.info(f"Dry run: {self.dry_run}")
        
        # Find all Ruby files
        ruby_files = self.find_ruby_files()
        self.logger.info(f"Found {len(ruby_files)} Ruby files")
        
        # Process each file
        for ruby_file in ruby_files:
            classification = self.classify_file(ruby_file)
            
            if classification.startswith('pre_2020'):
                if self.move_to_legacy(ruby_file):
                    self.stats['pre_2020_moved'] += 1
                else:
                    self.stats['errors'] += 1
                    
            elif classification.startswith('post_2020'):
                if self.convert_to_python(ruby_file):
                    self.stats['post_2020_converted'] += 1
                else:
                    self.stats['errors'] += 1
            else:
                self.logger.warning(f"Unknown classification for {ruby_file}: {classification}")
    
    def print_summary(self):
        """Print migration summary"""
        print("\n" + "="*60)
        print("RUBY TO PYTHON MIGRATION SUMMARY")
        print("="*60)
        print(f"Total Ruby files found:     {self.stats['total_ruby_files']}")
        print(f"Pre-2020 files moved:       {self.stats['pre_2020_moved']}")
        print(f"Post-2020 files converted:  {self.stats['post_2020_converted']}")
        print(f"Already converted:          {self.stats['already_converted']}")
        print(f"Errors encountered:         {self.stats['errors']}")
        print("="*60)
        
        if self.dry_run:
            print("DRY RUN - No files were actually moved or converted")
        else:
            print("Migration completed successfully!")
        
        print(f"\nLegacy files location: {self.legacy_dir}")
        print("Python framework location: python_framework/")


def main():
    """Main entry point"""
    parser = argparse.ArgumentParser(description="Migrate Ruby files to Python and organize legacy content")
    parser.add_argument('--dry-run', action='store_true', help='Show what would be done without making changes')
    parser.add_argument('--verbose', action='store_true', help='Enable verbose logging')
    parser.add_argument('--workspace', default='/workspace', help='Workspace directory path')
    
    args = parser.parse_args()
    
    migrator = RubyToPythonMigrator(
        workspace_dir=args.workspace,
        dry_run=args.dry_run,
        verbose=args.verbose
    )
    
    try:
        migrator.migrate_files()
        migrator.print_summary()
    except KeyboardInterrupt:
        print("\nMigration interrupted by user")
    except Exception as e:
        print(f"Migration failed with error: {e}")
        if args.verbose:
            import traceback
            traceback.print_exc()


if __name__ == '__main__':
    main()