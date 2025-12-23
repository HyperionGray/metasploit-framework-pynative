#!/usr/bin/env python3
"""
Comprehensive Ruby to Python Conversion for Metasploit Framework
Executes the conversion of all post-2020 Ruby files to Python
"""

import os
import sys
import subprocess
from pathlib import Path

def main():
    """Execute the comprehensive Ruby to Python conversion"""
    workspace = Path("/workspace")
    
    print("="*80)
    print("COMPREHENSIVE RUBY TO PYTHON CONVERSION")
    print("="*80)
    print(f"Workspace: {workspace}")
    print("Target: All Ruby files after 2020")
    print("="*80)
    
    # First, run a dry-run to see what would be converted
    print("\n1. RUNNING DRY-RUN ASSESSMENT...")
    print("-" * 40)
    
    try:
        result = subprocess.run([
            sys.executable, 
            str(workspace / "batch_ruby_to_python_converter.py"),
            "--dry-run"
        ], capture_output=True, text=True, cwd=workspace)
        
        print("DRY-RUN OUTPUT:")
        print(result.stdout)
        if result.stderr:
            print("DRY-RUN ERRORS:")
            print(result.stderr)
        
        if result.returncode != 0:
            print(f"Dry-run failed with return code: {result.returncode}")
            return False
            
    except Exception as e:
        print(f"Error running dry-run: {e}")
        return False
    
    # Ask for confirmation
    print("\n2. CONFIRMATION")
    print("-" * 40)
    response = input("Proceed with actual conversion? (y/N): ").strip().lower()
    
    if response != 'y':
        print("Conversion cancelled by user.")
        return False
    
    # Execute the actual conversion
    print("\n3. EXECUTING CONVERSION...")
    print("-" * 40)
    
    try:
        result = subprocess.run([
            sys.executable, 
            str(workspace / "batch_ruby_to_python_converter.py")
        ], cwd=workspace)
        
        if result.returncode == 0:
            print("\n✓ Conversion completed successfully!")
            return True
        else:
            print(f"\n✗ Conversion failed with return code: {result.returncode}")
            return False
            
    except Exception as e:
        print(f"Error running conversion: {e}")
        return False

if __name__ == '__main__':
    success = main()
    sys.exit(0 if success else 1)