#!/usr/bin/env python3
import subprocess
import sys
import os

def run_discovery():
    """Run the Ruby file discovery script"""
    try:
        print("=== PYTHON ROUND 2: RUBY FILE DISCOVERY ===")
        print("Discovering remaining Ruby files for conversion...")
        print()
        
        # Change to workspace directory
        os.chdir("/workspace")
        
        # Run the discovery script
        result = subprocess.run([sys.executable, "find_ruby_files.py"], 
                              capture_output=True, text=True)
        
        if result.returncode == 0:
            print(result.stdout)
            return True
        else:
            print(f"Discovery failed with error: {result.stderr}")
            return False
            
    except Exception as e:
        print(f"Error running discovery: {e}")
        return False

if __name__ == "__main__":
    success = run_discovery()
    if success:
        print("\n=== DISCOVERY COMPLETE ===")
        print("Ready to proceed with migration...")
    else:
        print("\n=== DISCOVERY FAILED ===")
        sys.exit(1)