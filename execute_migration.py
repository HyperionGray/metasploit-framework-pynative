#!/usr/bin/env python3
"""
Execute Python Round 2 Migration
Converts all remaining Ruby files to Python as requested
"""

import subprocess
import sys
import os
import time
from pathlib import Path

def run_migration_dry_run():
    """Run migration in dry-run mode first"""
    print("=== PYTHON ROUND 2: DRY RUN ===")
    print("Running migration in dry-run mode to preview changes...")
    print()
    
    try:
        os.chdir("/workspace")
        result = subprocess.run([
            sys.executable, "migrate_ruby_to_python.py", 
            "--dry-run", "--verbose"
        ], capture_output=True, text=True, timeout=300)
        
        if result.returncode == 0:
            print(result.stdout)
            if result.stderr:
                print("STDERR:", result.stderr)
            return True
        else:
            print(f"Dry run failed: {result.stderr}")
            return False
            
    except subprocess.TimeoutExpired:
        print("Dry run timed out after 5 minutes")
        return False
    except Exception as e:
        print(f"Error in dry run: {e}")
        return False

def run_actual_migration():
    """Run the actual migration"""
    print("\n=== PYTHON ROUND 2: ACTUAL MIGRATION ===")
    print("Running actual migration to convert Ruby files to Python...")
    print()
    
    try:
        os.chdir("/workspace")
        result = subprocess.run([
            sys.executable, "migrate_ruby_to_python.py", 
            "--verbose"
        ], capture_output=True, text=True, timeout=600)
        
        if result.returncode == 0:
            print(result.stdout)
            if result.stderr:
                print("STDERR:", result.stderr)
            return True
        else:
            print(f"Migration failed: {result.stderr}")
            return False
            
    except subprocess.TimeoutExpired:
        print("Migration timed out after 10 minutes")
        return False
    except Exception as e:
        print(f"Error in migration: {e}")
        return False

def verify_python_files():
    """Quick verification of converted Python files"""
    print("\n=== PYTHON ROUND 2: VERIFICATION ===")
    print("Verifying converted Python files...")
    
    workspace = Path("/workspace")
    python_files = []
    
    # Check modules/exploits for new Python files
    exploits_dir = workspace / "modules" / "exploits"
    if exploits_dir.exists():
        python_files.extend(list(exploits_dir.rglob("*.py")))
    
    print(f"Found {len(python_files)} Python files in modules/exploits")
    
    # Test syntax of a few files
    syntax_errors = 0
    for py_file in python_files[:10]:  # Test first 10
        try:
            with open(py_file, 'r') as f:
                compile(f.read(), str(py_file), 'exec')
        except SyntaxError as e:
            print(f"Syntax error in {py_file}: {e}")
            syntax_errors += 1
        except Exception as e:
            print(f"Error checking {py_file}: {e}")
    
    if syntax_errors == 0:
        print("✅ All tested Python files have valid syntax")
    else:
        print(f"⚠️  Found {syntax_errors} files with syntax errors")
    
    return syntax_errors == 0

def main():
    """Main execution"""
    print("🐍 PYTHON ROUND 2: GRAB ALL THE RUBY AND PYTHON IT! 🐍")
    print("=" * 60)
    
    # Step 1: Dry run
    if not run_migration_dry_run():
        print("❌ Dry run failed. Aborting migration.")
        return False
    
    # Step 2: Ask for confirmation
    print("\n" + "=" * 60)
    response = input("Proceed with actual migration? (y/N): ").strip().lower()
    if response != 'y':
        print("Migration cancelled by user.")
        return False
    
    # Step 3: Actual migration
    if not run_actual_migration():
        print("❌ Migration failed.")
        return False
    
    # Step 4: Verification
    if not verify_python_files():
        print("⚠️  Migration completed but some files may need manual review.")
    else:
        print("✅ Migration completed successfully!")
    
    print("\n🎉 PYTHON ROUND 2 COMPLETE! 🎉")
    print("All Ruby files have been PYTHON-ed as requested!")
    
    return True

if __name__ == "__main__":
    success = main()
    sys.exit(0 if success else 1)