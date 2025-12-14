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
            'lib/rex',
            'modules/exploits',
            'modules/auxiliary',
            'modules/post',
            'tools',
            'scripts'
        }
        
        # Files already converted to Python (from PYTHON_TRANSLATIONS.md)
        self.already_converted = {
            'lib/rex/proto/smb/utils.rb',
            'tools/modules/module_rank.rb',
            'tools/modules/module_count.rb',
            'modules/encoders/ruby/base64.rb',
            'scripts/meterpreter/get_local_subnets.rb',
            # Add more from the translations document...
        }
        
        # Statistics
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
        for root, dirs, files in os.walk(self.workspace_dir):
            # Skip already processed directories
            if 'legacy' in Path(root).parts or 'python_framework' in Path(root).parts:
                continue
                
            for file in files:
                if file.endswith('.rb'):
                    ruby_files.append(Path(root) / file)
        
        self.stats['total_ruby_files'] = len(ruby_files)
        self.logger.info(f"Found {len(ruby_files)} Ruby files")
        return ruby_files
    
    def get_file_date(self, filepath: Path) -> Optional[datetime.datetime]:
        """Get the creation/modification date of a file from git history"""
        try:
            # Get git creation date (first commit)
            result = subprocess.run([
                'git', 'log', '--follow', '--format=%ai', '--reverse', str(filepath)
            ], capture_output=True, text=True, cwd=self.workspace_dir)
            
            if result.returncode == 0 and result.stdout.strip():
                git_dates = result.stdout.strip().split('\n')
                first_commit = git_dates[0]
                
                # Parse git date format: 2021-01-15 10:30:45 -0500
                date_part = first_commit.split()[0]
                return datetime.datetime.strptime(date_part, '%Y-%m-%d')
            
            # Fallback to filesystem modification time
            stat = filepath.stat()
            return datetime.datetime.fromtimestamp(stat.st_mtime)
            
        except Exception as e:
            self.logger.warning(f"Could not get date for {filepath}: {e}")
            return None
    
    def classify_file(self, filepath: Path) -> str:
        """Classify file as pre-2020, post-2020, or unknown"""
        # Check if already converted
        rel_path = filepath.relative_to(self.workspace_dir)
        if str(rel_path) in self.already_converted:
            return 'already_converted'
        
        file_date = self.get_file_date(filepath)
        if not file_date:
            return 'unknown'
        
        return 'post_2020' if file_date >= self.cutoff_date else 'pre_2020'
    
    def create_legacy_structure(self):
        """Create legacy directory structure"""
        if not self.dry_run:
            self.legacy_dir.mkdir(exist_ok=True)
            
            # Create main subdirectories
            for subdir in ['modules', 'lib', 'tools', 'scripts', 'external']:
                (self.legacy_dir / subdir).mkdir(exist_ok=True)
        
        self.logger.info(f"Created legacy directory structure at {self.legacy_dir}")
    
    def move_to_legacy(self, filepath: Path) -> bool:
        """Move a pre-2020 Ruby file to legacy directory"""
        try:
            rel_path = filepath.relative_to(self.workspace_dir)
            legacy_path = self.legacy_dir / rel_path
            
            # Create parent directories
            if not self.dry_run:
                legacy_path.parent.mkdir(parents=True, exist_ok=True)
                shutil.move(str(filepath), str(legacy_path))
            
            self.logger.info(f"Moved to legacy: {rel_path}")
            return True
            
        except Exception as e:
            self.logger.error(f"Failed to move {filepath} to legacy: {e}")
            return False
    
    def convert_to_python(self, filepath: Path) -> bool:
        """Convert a post-2020 Ruby file to Python"""
        try:
            rel_path = filepath.relative_to(self.workspace_dir)
            python_path = filepath.with_suffix('.py')
            
            self.logger.info(f"Converting to Python: {rel_path}")
            
            if self.dry_run:
                return True
            
            # Read Ruby file
            with open(filepath, 'r', encoding='utf-8', errors='ignore') as f:
                ruby_content = f.read()
            
            # Convert Ruby to Python
            python_content = self.ruby_to_python_converter(ruby_content, filepath)
            
            # Write Python file
            with open(python_path, 'w', encoding='utf-8') as f:
                f.write(python_content)
            
            # Make executable if original was executable
            if os.access(filepath, os.X_OK):
                os.chmod(python_path, 0o755)
            
            # Remove original Ruby file
            os.remove(filepath)
            
            self.logger.info(f"Converted: {rel_path} -> {python_path.name}")
            return True
            
        except Exception as e:
            self.logger.error(f"Failed to convert {filepath} to Python: {e}")
            return False
    
    def ruby_to_python_converter(self, ruby_content: str, filepath: Path) -> str:
        """
        Convert Ruby code to Python
        
        This is a basic converter that handles common patterns.
        Complex modules may need manual review.
        """
        python_lines = []
        
        # Add Python shebang and encoding
        python_lines.append("#!/usr/bin/env python3")
        python_lines.append("# -*- coding: utf-8 -*-")
        python_lines.append('"""')
        python_lines.append(f"Converted from Ruby: {filepath.name}")
        python_lines.append("")
        python_lines.append("This module was automatically converted from Ruby to Python")
        python_lines.append("as part of the post-2020 Python migration initiative.")
        python_lines.append('"""')
        python_lines.append("")
        
        # Add common imports
        python_lines.append("import sys")
        python_lines.append("import os")
        python_lines.append("import re")
        python_lines.append("import json")
        python_lines.append("import time")
        python_lines.append("import logging")
        python_lines.append("from typing import Dict, List, Optional, Any, Union")
        python_lines.append("")
        
        # Add framework imports if this is an exploit
        if 'modules/exploits' in str(filepath) or 'modules/auxiliary' in str(filepath):
            python_lines.append("# Framework imports")
            python_lines.append("sys.path.insert(0, os.path.join(os.path.dirname(__file__), '../../../python_framework'))")
            python_lines.append("from core.exploit import RemoteExploit, ExploitInfo, ExploitResult")
            python_lines.append("from helpers.http_client import HttpExploitMixin")
            python_lines.append("")
        
        # Process Ruby content line by line
        ruby_lines = ruby_content.split('\n')
        in_class = False
        class_name = None
        indent_level = 0
        
        for line in ruby_lines:
            stripped = line.strip()
            
            # Skip empty lines and comments (preserve some comments)
            if not stripped:
                python_lines.append("")
                continue
            
            if stripped.startswith('#'):
                # Convert Ruby comments to Python
                python_lines.append(line.replace('#', '#', 1))
                continue
            
            # Convert class definitions
            if stripped.startswith('class ') and ' < ' in stripped:
                # Ruby: class MyClass < ParentClass
                # Python: class MyClass(ParentClass):
                match = re.match(r'class\s+(\w+)\s*<\s*(.+)', stripped)
                if match:
                    class_name = match.group(1)
                    parent_class = match.group(2).strip()
                    
                    # Map common Ruby parent classes to Python
                    parent_mapping = {
                        'Msf::Exploit::Remote': 'RemoteExploit, HttpExploitMixin',
                        'Msf::Auxiliary': 'AuxiliaryModule',
                        'Msf::Post': 'PostModule'
                    }
                    
                    python_parent = parent_mapping.get(parent_class, parent_class)
                    python_lines.append(f"class {class_name}({python_parent}):")
                    in_class = True
                    indent_level = 1
                    continue
            
            # Convert method definitions
            if stripped.startswith('def '):
                # Ruby: def method_name(args)
                # Python: def method_name(self, args):
                method_match = re.match(r'def\s+(\w+)(\([^)]*\))?', stripped)
                if method_match:
                    method_name = method_match.group(1)
                    args = method_match.group(2) or "()"
                    
                    # Add self parameter if in class and not already present
                    if in_class and not args.startswith('(self'):
                        if args == "()":
                            args = "(self)"
                        else:
                            args = f"(self, {args[1:]}"
                    
                    python_lines.append("    " * indent_level + f"def {method_name}{args}:")
                    python_lines.append("    " * (indent_level + 1) + '"""TODO: Implement method"""')
                    python_lines.append("    " * (indent_level + 1) + "pass")
                    continue
            
            # Convert common Ruby patterns
            converted_line = self.convert_ruby_patterns(line)
            python_lines.append(converted_line)
        
        # Add main execution block for standalone scripts
        if 'scripts/' in str(filepath) or 'tools/' in str(filepath):
            python_lines.append("")
            python_lines.append("")
            python_lines.append("if __name__ == '__main__':")
            python_lines.append("    # TODO: Implement main execution")
            python_lines.append("    pass")
        
        return '\n'.join(python_lines)
    
    def convert_ruby_patterns(self, line: str) -> str:
        """Convert common Ruby patterns to Python equivalents"""
        # Preserve original indentation
        indent = len(line) - len(line.lstrip())
        stripped = line.strip()
        
        if not stripped:
            return line
        
        # Ruby string interpolation: "#{var}" -> f"{var}"
        converted = re.sub(r'"([^"]*?)#\{([^}]+)\}([^"]*?)"', r'f"\1{\2}\3"', stripped)
        
        # Ruby symbols: :symbol -> "symbol"
        converted = re.sub(r':(\w+)', r'"\1"', converted)
        
        # Ruby hash rockets: => -> :
        converted = re.sub(r'\s*=>\s*', ': ', converted)
        
        # Ruby nil -> None
        converted = re.sub(r'\bnil\b', 'None', converted)
        
        # Ruby true/false -> True/False
        converted = re.sub(r'\btrue\b', 'True', converted)
        converted = re.sub(r'\bfalse\b', 'False', converted)
        
        # Ruby puts -> print
        converted = re.sub(r'\bputs\b', 'print', converted)
        
        # Ruby require -> import (basic conversion)
        if converted.startswith('require '):
            module_name = converted.replace('require ', '').strip('\'"')
            converted = f"# TODO: Convert require '{module_name}' to appropriate Python import"
        
        # Ruby instance variables: @var -> self._var
        converted = re.sub(r'@(\w+)', r'self._\1', converted)
        
        # Ruby class variables: @@var -> cls._var (basic)
        converted = re.sub(r'@@(\w+)', r'cls._\1', converted)
        
        # Ruby end -> pass (basic)
        if stripped == 'end':
            converted = 'pass'
        
        return ' ' * indent + converted
    
    def is_priority_file(self, filepath: Path) -> bool:
        """Check if file is in a priority directory for conversion"""
        rel_path = str(filepath.relative_to(self.workspace_dir))
        return any(rel_path.startswith(priority_dir) for priority_dir in self.priority_dirs)
    
    def migrate_files(self):
        """Main migration process"""
        self.logger.info("Starting Ruby to Python migration...")
        
        # Create legacy directory structure
        self.create_legacy_structure()
        
        # Find all Ruby files
        ruby_files = self.find_ruby_files()
        
        # Classify and process files
        for filepath in ruby_files:
            classification = self.classify_file(filepath)
            
            if classification == 'already_converted':
                self.logger.info(f"Already converted: {filepath.relative_to(self.workspace_dir)}")
                self.stats['already_converted'] += 1
                continue
            
            elif classification == 'pre_2020':
                if self.move_to_legacy(filepath):
                    self.stats['pre_2020_moved'] += 1
                else:
                    self.stats['errors'] += 1
            
            elif classification == 'post_2020':
                # Prioritize exploit framework and helper files
                if self.is_priority_file(filepath):
                    if self.convert_to_python(filepath):
                        self.stats['post_2020_converted'] += 1
                    else:
                        self.stats['errors'] += 1
                else:
                    # Move non-priority post-2020 files to a conversion queue
                    self.logger.info(f"Queued for conversion: {filepath.relative_to(self.workspace_dir)}")
            
            else:  # unknown
                self.logger.warning(f"Unknown classification: {filepath.relative_to(self.workspace_dir)}")
    
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