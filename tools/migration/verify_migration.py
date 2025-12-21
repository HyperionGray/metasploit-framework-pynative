#!/usr/bin/env python3
"""
Verification script for Ruby to Python migration
"""

import os
import sys
import json
import subprocess
from pathlib import Path
from typing import Dict, List, Optional, Tuple
import argparse


class MigrationVerifier:
    """Verifies the Ruby to Python migration results"""
    
    def __init__(self, workspace_dir: str = "/workspace"):
        self.workspace_dir = Path(workspace_dir)
        self.legacy_dir = self.workspace_dir / "legacy"
        self.python_framework_dir = self.workspace_dir / "python_framework"
        
        self.results = {
            'ruby_files_remaining': [],
            'python_files_created': [],
            'legacy_files_moved': [],
            'conversion_errors': [],
            'verification_passed': False
        }
    
    def find_remaining_ruby_files(self) -> List[Path]:
        """Find Ruby files that weren't migrated"""
        ruby_files = []
        
        # Search in main directories (excluding legacy and test directories)
        for ruby_file in self.workspace_dir.rglob("*.rb"):
            # Skip files in legacy, spec, test directories
            if not any(skip_dir in str(ruby_file) for skip_dir in 
                      ['legacy/', 'spec/', 'test/', '.git/', 'vendor/']):
                ruby_files.append(ruby_file)
        
        return ruby_files
    
    def find_python_files(self) -> List[Path]:
        """Find Python files created during migration"""
        python_files = []
        
        # Look for .py files in modules and lib directories
        for python_file in self.workspace_dir.rglob("*.py"):
            if any(target_dir in str(python_file) for target_dir in 
                  ['modules/', 'lib/', 'python_framework/']):
                python_files.append(python_file)
        
        return python_files
    
    def find_legacy_files(self) -> List[Path]:
        """Find files moved to legacy directory"""
        if not self.legacy_dir.exists():
            return []
        
        return list(self.legacy_dir.rglob("*.rb"))
    
    def verify_python_syntax(self, python_file: Path) -> bool:
        """Verify Python file has valid syntax"""
        try:
            result = subprocess.run([
                sys.executable, '-m', 'py_compile', str(python_file)
            ], capture_output=True, text=True)
            return result.returncode == 0
        except Exception:
            return False
    
    def check_migration_script_exists(self) -> bool:
        """Check if migration script exists and is accessible"""
        migration_script = Path("/workspace/tools/migration/migrate_ruby_to_python.py")
        return migration_script.exists() and migration_script.is_file()
    
    def run_verification(self) -> Dict:
        """Run complete verification process"""
        print("Starting migration verification...")
        
        # Check migration script
        if not self.check_migration_script_exists():
            self.results['conversion_errors'].append("Migration script not found in tools/migration/")
        
        # Find remaining Ruby files
        self.results['ruby_files_remaining'] = self.find_remaining_ruby_files()
        
        # Find created Python files
        self.results['python_files_created'] = self.find_python_files()
        
        # Find legacy files
        self.results['legacy_files_moved'] = self.find_legacy_files()
        
        # Verify Python syntax
        syntax_errors = []
        for python_file in self.results['python_files_created']:
            if not self.verify_python_syntax(python_file):
                syntax_errors.append(str(python_file))
        
        if syntax_errors:
            self.results['conversion_errors'].extend(syntax_errors)
        
        # Determine if verification passed
        self.results['verification_passed'] = (
            len(self.results['conversion_errors']) == 0 and
            len(self.results['python_files_created']) > 0
        )
        
        return self.results
    
    def print_report(self):
        """Print verification report"""
        print("\n" + "="*60)
        print("MIGRATION VERIFICATION REPORT")
        print("="*60)
        
        print(f"Ruby files remaining:     {len(self.results['ruby_files_remaining'])}")
        print(f"Python files created:     {len(self.results['python_files_created'])}")
        print(f"Legacy files moved:       {len(self.results['legacy_files_moved'])}")
        print(f"Conversion errors:        {len(self.results['conversion_errors'])}")
        
        if self.results['conversion_errors']:
            print("\nErrors found:")
            for error in self.results['conversion_errors']:
                print(f"  - {error}")
        
        print(f"\nVerification: {'PASSED' if self.results['verification_passed'] else 'FAILED'}")
        print("="*60)
    
    def save_report(self, output_file: str):
        """Save verification report to JSON file"""
        # Convert Path objects to strings for JSON serialization
        json_results = {}
        for key, value in self.results.items():
            if isinstance(value, list) and value and isinstance(value[0], Path):
                json_results[key] = [str(path) for path in value]
            else:
                json_results[key] = value
        
        with open(output_file, 'w') as f:
            json.dump(json_results, f, indent=2)
        
        print(f"Report saved to: {output_file}")


def main():
    """Main entry point"""
    parser = argparse.ArgumentParser(description="Verify Ruby to Python migration results")
    parser.add_argument('--workspace', default='/workspace', help='Workspace directory path')
    parser.add_argument('--output', help='Output file for JSON report')
    
    args = parser.parse_args()
    
    verifier = MigrationVerifier(workspace_dir=args.workspace)
    
    try:
        results = verifier.run_verification()
        verifier.print_report()
        
        if args.output:
            verifier.save_report(args.output)
        
        # Exit with error code if verification failed
        sys.exit(0 if results['verification_passed'] else 1)
        
    except Exception as e:
        print(f"Verification failed with error: {e}")
        import traceback
        traceback.print_exc()
        sys.exit(1)


if __name__ == '__main__':
    main()