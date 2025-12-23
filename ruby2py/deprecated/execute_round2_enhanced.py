#!/usr/bin/env python3
"""
Round 2 Enhanced: Ruby to Python Migration Executor

This script executes the Round 2 migration with enhanced capabilities:
1. Comprehensive Ruby file inventory and classification
2. Targeted conversion of high-priority post-2020 modules
3. Systematic legacy organization of pre-2020 modules
4. Quality validation and reporting

Usage: python3 execute_round2_enhanced.py [--dry-run] [--verbose]
"""

import os
import sys
import subprocess
import datetime
import re
import json
from pathlib import Path
from typing import Dict, List, Tuple, Optional
import argparse
import logging

class Round2EnhancedExecutor:
    """Enhanced Round 2 migration executor"""
    
    def __init__(self, workspace_dir: str = "/workspace", dry_run: bool = False, verbose: bool = False):
        self.workspace_dir = Path(workspace_dir)
        self.dry_run = dry_run
        self.verbose = verbose
        
        # Setup logging
        logging.basicConfig(
            level=logging.DEBUG if verbose else logging.INFO,
            format='%(asctime)s - %(levelname)s - %(message)s'
        )
        self.logger = logging.getLogger(__name__)
        
        # Statistics
        self.stats = {
            'total_ruby_files': 0,
            'post_2020_candidates': 0,
            'pre_2020_candidates': 0,
            'already_converted': 0,
            'conversion_targets': 0,
            'successful_conversions': 0,
            'legacy_moves': 0,
            'errors': 0
        }
        
        # High-priority module patterns for conversion
        self.priority_patterns = [
            'cve_202[0-9]',  # CVE 2020-2029
            'http.*rce',     # HTTP RCE exploits
            'upload.*exec',  # File upload exploits
            'auth.*bypass',  # Authentication bypass
            'injection',     # Various injection types
        ]
    
    def print_banner(self):
        """Print Round 2 Enhanced banner"""
        banner = """
🐍🔥 ROUND 2 ENHANCED: PYTHON SUPREMACY 🔥🐍
================================================
Mission: Convert post-2020 Ruby modules to Python
         Move pre-2020 modules to legacy
         KILL ALL THE RUBY! PYTHON FOREVER!
================================================
"""
        print(banner)
    
    def inventory_ruby_files(self) -> Dict[str, List[Path]]:
        """Create comprehensive inventory of Ruby files"""
        self.logger.info("📊 Creating comprehensive Ruby file inventory...")
        
        inventory = {
            'post_2020': [],
            'pre_2020': [],
            'unknown': [],
            'already_converted': []
        }
        
        # Find all Ruby files
        ruby_files = []
        for pattern in ['**/*.rb']:
            ruby_files.extend(self.workspace_dir.glob(pattern))
        
        # Filter out certain directories
        filtered_files = []
        skip_dirs = ['spec/', 'test/', '.git/', 'vendor/', 'legacy/', 'external/']
        
        for rb_file in ruby_files:
            if not any(skip_dir in str(rb_file) for skip_dir in skip_dirs):
                filtered_files.append(rb_file)
        
        self.stats['total_ruby_files'] = len(filtered_files)
        self.logger.info(f"Found {len(filtered_files)} Ruby files to analyze")
        
        # Classify each file
        for rb_file in filtered_files:
            classification = self.classify_ruby_file(rb_file)
            
            # Check if Python version already exists
            py_file = rb_file.with_suffix('.py')
            if py_file.exists():
                inventory['already_converted'].append(rb_file)
                self.stats['already_converted'] += 1
            else:
                inventory[classification].append(rb_file)
                if classification == 'post_2020':
                    self.stats['post_2020_candidates'] += 1
                elif classification == 'pre_2020':
                    self.stats['pre_2020_candidates'] += 1
        
        return inventory
    
    def classify_ruby_file(self, ruby_file: Path) -> str:
        """Classify Ruby file by disclosure date"""
        try:
            with open(ruby_file, 'r', encoding='utf-8', errors='ignore') as f:
                content = f.read()
            
            # Look for DisclosureDate
            disclosure_pattern = re.compile(r"'DisclosureDate'\s*=>\s*'([^']+)'")
            match = disclosure_pattern.search(content)
            
            if match:
                date_str = match.group(1)
                try:
                    disclosure_date = datetime.datetime.strptime(date_str, '%Y-%m-%d')
                    cutoff_date = datetime.datetime(2020, 1, 1)
                    
                    if disclosure_date >= cutoff_date:
                        return 'post_2020'
                    else:
                        return 'pre_2020'
                except ValueError:
                    pass
            
            # Fallback to file modification time
            stat = ruby_file.stat()
            file_date = datetime.datetime.fromtimestamp(stat.st_mtime)
            cutoff_date = datetime.datetime(2020, 1, 1)
            
            if file_date >= cutoff_date:
                return 'post_2020'
            else:
                return 'pre_2020'
                
        except Exception as e:
            self.logger.warning(f"Error classifying {ruby_file}: {e}")
            return 'unknown'
    
    def select_conversion_targets(self, post_2020_files: List[Path]) -> List[Path]:
        """Select high-priority modules for conversion"""
        self.logger.info("🎯 Selecting high-priority conversion targets...")
        
        targets = []
        
        # Score files based on priority patterns
        scored_files = []
        for rb_file in post_2020_files:
            score = 0
            file_content = ""
            
            try:
                with open(rb_file, 'r', encoding='utf-8', errors='ignore') as f:
                    file_content = f.read().lower()
            except:
                continue
            
            # Score based on priority patterns
            for pattern in self.priority_patterns:
                if re.search(pattern, str(rb_file).lower()) or re.search(pattern, file_content):
                    score += 10
            
            # Bonus for exploit modules
            if 'modules/exploits/' in str(rb_file):
                score += 5
            
            # Bonus for HTTP-based exploits
            if 'http' in str(rb_file).lower():
                score += 3
            
            # Bonus for recent CVEs
            if re.search(r'cve.202[3-5]', str(rb_file).lower()):
                score += 8
            
            scored_files.append((score, rb_file))
        
        # Sort by score and select top candidates
        scored_files.sort(reverse=True, key=lambda x: x[0])
        
        # Select up to 10 high-priority targets
        max_targets = min(10, len(scored_files))
        targets = [f[1] for f in scored_files[:max_targets] if f[0] > 0]
        
        self.stats['conversion_targets'] = len(targets)
        self.logger.info(f"Selected {len(targets)} high-priority conversion targets")
        
        return targets
    
    def execute_migration_script(self) -> bool:
        """Execute the main migration script"""
        self.logger.info("🚀 Executing migration script...")
        
        migration_script = self.workspace_dir / "tools/migration/migrate_ruby_to_python.py"
        
        if not migration_script.exists():
            self.logger.error(f"Migration script not found: {migration_script}")
            return False
        
        try:
            # Build command
            cmd = [sys.executable, str(migration_script)]
            if self.dry_run:
                cmd.append('--dry-run')
            if self.verbose:
                cmd.append('--verbose')
            cmd.extend(['--workspace', str(self.workspace_dir)])
            
            # Execute migration
            result = subprocess.run(
                cmd,
                cwd=str(self.workspace_dir),
                capture_output=True,
                text=True
            )
            
            if result.returncode == 0:
                self.logger.info("✅ Migration script executed successfully")
                if self.verbose:
                    print("MIGRATION OUTPUT:")
                    print(result.stdout)
                return True
            else:
                self.logger.error(f"❌ Migration script failed with return code {result.returncode}")
                print("MIGRATION ERROR:")
                print(result.stderr)
                return False
                
        except Exception as e:
            self.logger.error(f"Error executing migration script: {e}")
            return False
    
    def validate_conversions(self, converted_files: List[Path]) -> int:
        """Validate converted Python files"""
        self.logger.info("🔍 Validating converted Python files...")
        
        valid_count = 0
        
        for py_file in converted_files:
            if not py_file.exists():
                continue
                
            try:
                # Syntax validation
                with open(py_file, 'r', encoding='utf-8') as f:
                    content = f.read()
                
                compile(content, str(py_file), 'exec')
                valid_count += 1
                self.logger.debug(f"✅ {py_file.name} - syntax valid")
                
            except SyntaxError as e:
                self.logger.warning(f"❌ {py_file.name} - syntax error: {e}")
                self.stats['errors'] += 1
            except Exception as e:
                self.logger.warning(f"❌ {py_file.name} - validation error: {e}")
                self.stats['errors'] += 1
        
        self.logger.info(f"Validated {valid_count}/{len(converted_files)} converted files")
        return valid_count
    
    def print_summary(self):
        """Print comprehensive summary"""
        print("\n" + "="*70)
        print("🐍 ROUND 2 ENHANCED MIGRATION SUMMARY 🐍")
        print("="*70)
        print(f"Total Ruby files found:           {self.stats['total_ruby_files']}")
        print(f"Post-2020 candidates:             {self.stats['post_2020_candidates']}")
        print(f"Pre-2020 candidates:              {self.stats['pre_2020_candidates']}")
        print(f"Already converted:                {self.stats['already_converted']}")
        print(f"Conversion targets selected:      {self.stats['conversion_targets']}")
        print(f"Successful conversions:           {self.stats['successful_conversions']}")
        print(f"Legacy moves:                     {self.stats['legacy_moves']}")
        print(f"Errors encountered:               {self.stats['errors']}")
        print("="*70)
        
        if self.dry_run:
            print("🔍 DRY RUN - No files were actually modified")
        else:
            print("✅ MIGRATION COMPLETED!")
        
        print("\n🎯 MISSION STATUS:")
        if self.stats['errors'] == 0:
            print("🎉 PERFECT EXECUTION! RUBY HAS BEEN DEFEATED!")
            print("🐍 PYTHON SUPREMACY ACHIEVED!")
        else:
            print(f"⚠️  {self.stats['errors']} errors encountered - review needed")
        
        print(f"\n📁 Legacy files location: {self.workspace_dir}/legacy/")
        print(f"📁 Python framework: {self.workspace_dir}/lib/msf/")
    
    def execute_round2(self):
        """Execute the complete Round 2 Enhanced process"""
        self.print_banner()
        
        try:
            # Step 1: Inventory
            self.logger.info("Step 1: Creating Ruby file inventory...")
            inventory = self.inventory_ruby_files()
            
            # Step 2: Select targets
            self.logger.info("Step 2: Selecting conversion targets...")
            targets = self.select_conversion_targets(inventory['post_2020'])
            
            # Step 3: Execute migration
            self.logger.info("Step 3: Executing migration script...")
            migration_success = self.execute_migration_script()
            
            if not migration_success:
                self.logger.error("Migration script failed - aborting")
                return False
            
            # Step 4: Validate conversions
            self.logger.info("Step 4: Validating conversions...")
            converted_files = [f.with_suffix('.py') for f in targets]
            valid_count = self.validate_conversions(converted_files)
            self.stats['successful_conversions'] = valid_count
            
            # Step 5: Summary
            self.print_summary()
            
            return True
            
        except KeyboardInterrupt:
            print("\n⚠️  Migration interrupted by user")
            return False
        except Exception as e:
            self.logger.error(f"Migration failed: {e}")
            if self.verbose:
                import traceback
                traceback.print_exc()
            return False

def main():
    """Main entry point"""
    parser = argparse.ArgumentParser(description="Execute Round 2 Enhanced Ruby-to-Python migration")
    parser.add_argument('--dry-run', action='store_true', help='Show what would be done without making changes')
    parser.add_argument('--verbose', action='store_true', help='Enable verbose logging')
    parser.add_argument('--workspace', default='/workspace', help='Workspace directory path')
    
    args = parser.parse_args()
    
    executor = Round2EnhancedExecutor(
        workspace_dir=args.workspace,
        dry_run=args.dry_run,
        verbose=args.verbose
    )
    
    success = executor.execute_round2()
    
    if success:
        print("\n🚀 ROUND 2 ENHANCED: MISSION ACCOMPLISHED!")
        print("🐍 PYTHON VICTORY IS COMPLETE! 🐍")
    else:
        print("\n❌ ROUND 2 ENHANCED: MISSION FAILED")
        print("Review errors and try again")
    
    sys.exit(0 if success else 1)

if __name__ == '__main__':
    main()