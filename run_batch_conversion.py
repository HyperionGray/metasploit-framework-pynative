#!/usr/bin/env python3
"""Run the batch conversion process"""

import subprocess
import sys
import os

def run_conversion(dry_run=True):
    """Run the batch conversion"""
    
    os.chdir('/workspace')
    
    cmd = [sys.executable, 'batch_ruby_to_python_converter.py']
    if dry_run:
        cmd.append('--dry-run')
    
    print(f"Running command: {' '.join(cmd)}")
    print("=" * 60)
    
    result = subprocess.run(cmd, capture_output=True, text=True)
    
    print("STDOUT:")
    print(result.stdout)
    
    if result.stderr:
        print("\nSTDERR:")
        print(result.stderr)
    
    print(f"\nReturn code: {result.returncode}")
    
    return result.returncode == 0

if __name__ == '__main__':
    # First run in dry-run mode
    print("Running DRY RUN to see what would be converted...")
    success = run_conversion(dry_run=True)
    
    if success:
        print("\n" + "="*60)
        print("DRY RUN COMPLETED SUCCESSFULLY")
        print("="*60)
        
        # Ask if we should proceed with actual conversion
        response = input("\nProceed with actual conversion? (y/N): ").strip().lower()
        if response == 'y':
            print("\nRunning ACTUAL CONVERSION...")
            print("="*60)
            run_conversion(dry_run=False)
        else:
            print("Conversion cancelled by user.")
    else:
        print("DRY RUN FAILED - check errors above")