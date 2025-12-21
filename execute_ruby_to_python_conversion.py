#!/usr/bin/env python3
"""
Execute Ruby to Python conversion for post-2020 files
"""

import os
import sys
import subprocess
from pathlib import Path

def run_conversion():
    """Run the batch Ruby to Python conversion"""
    workspace = Path("/workspace")
    converter_script = workspace / "batch_ruby_to_python_converter.py"
    
    if not converter_script.exists():
        print(f"Error: Converter script not found at {converter_script}")
        return False
    
    print("="*80)
    print("RUBY TO PYTHON CONVERSION - POST 2020 FILES")
    print("="*80)
    print(f"Workspace: {workspace}")
    print(f"Converter: {converter_script}")
    print("="*80)
    
    # First run dry-run
    print("\n1. DRY RUN - Checking what would be converted...")
    print("-" * 60)
    
    try:
        result = subprocess.run([
            sys.executable, str(converter_script), "--dry-run"
        ], cwd=workspace, text=True)
        
        if result.returncode != 0:
            print(f"Dry run failed with return code: {result.returncode}")
            return False
            
    except Exception as e:
        print(f"Error during dry run: {e}")
        return False
    
    print("\n2. ACTUAL CONVERSION - Converting Ruby files to Python...")
    print("-" * 60)
    
    try:
        result = subprocess.run([
            sys.executable, str(converter_script)
        ], cwd=workspace, text=True)
        
        if result.returncode == 0:
            print("\n" + "="*60)
            print("✓ CONVERSION COMPLETED SUCCESSFULLY!")
            print("="*60)
            return True
        else:
            print(f"\n✗ Conversion failed with return code: {result.returncode}")
            return False
            
    except Exception as e:
        print(f"Error during conversion: {e}")
        return False

if __name__ == '__main__':
    success = run_conversion()
    if success:
        print("\nAll post-2020 Ruby files have been converted to Python!")
        print("Ruby v Python: Round 1 - PYTHON WINS! 🐍")
    else:
        print("\nConversion encountered errors. Check the output above.")
    
    sys.exit(0 if success else 1)