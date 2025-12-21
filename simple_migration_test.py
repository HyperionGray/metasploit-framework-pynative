#!/usr/bin/env python3
"""
Simple test of the migration process on a single file
"""

import os
import sys
from pathlib import Path

# Add the workspace to Python path
sys.path.insert(0, '/workspace')

# Import the migrator
from migrate_ruby_to_python import RubyToPythonMigrator

def test_single_file_conversion():
    """Test conversion of a single Ruby file"""
    workspace = Path("/workspace")
    
    # Find a Ruby file to test with
    test_file = workspace / "modules" / "exploits" / "linux" / "http" / "apache_airflow_dag_rce.rb"
    
    if not test_file.exists():
        print(f"Test file not found: {test_file}")
        return False
    
    print(f"Testing conversion of: {test_file.name}")
    
    # Create migrator instance
    migrator = RubyToPythonMigrator(dry_run=True, verbose=True)
    
    # Test the conversion
    try:
        # Read the Ruby file
        with open(test_file, 'r', encoding='utf-8', errors='ignore') as f:
            ruby_content = f.read()
        
        print(f"Ruby file size: {len(ruby_content)} characters")
        
        # Convert to Python
        python_content = migrator.ruby_to_python_converter(ruby_content, test_file)
        
        print(f"Python conversion size: {len(python_content)} characters")
        print("\nFirst 500 characters of converted Python:")
        print("-" * 50)
        print(python_content[:500])
        print("-" * 50)
        
        return True
        
    except Exception as e:
        print(f"Error during conversion: {e}")
        return False

def run_dry_run_migration():
    """Run the full migration in dry-run mode"""
    print("\n=== RUNNING DRY-RUN MIGRATION ===")
    
    migrator = RubyToPythonMigrator(dry_run=True, verbose=True)
    
    try:
        migrator.migrate_files()
        migrator.print_summary()
        return True
    except Exception as e:
        print(f"Migration dry-run failed: {e}")
        return False

if __name__ == "__main__":
    print("🐍 PYTHON ROUND 2: TESTING MIGRATION 🐍")
    print("=" * 50)
    
    # Test single file conversion
    if test_single_file_conversion():
        print("✅ Single file conversion test passed")
    else:
        print("❌ Single file conversion test failed")
        sys.exit(1)
    
    # Run dry-run migration
    if run_dry_run_migration():
        print("✅ Dry-run migration completed")
    else:
        print("❌ Dry-run migration failed")
        sys.exit(1)
    
    print("\n🎉 All tests passed! Ready for actual migration.")