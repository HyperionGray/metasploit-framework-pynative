#!/usr/bin/env python3

import os
import sys
from pathlib import Path

def main():
    print("🥊 RUBY v PYTHON: ROUND 1: FIGHT! 🥊")
    print("=" * 60)
    print("Alright gang only 7.1k ruby files to go!! let's rock this potato!!!!!")
    print("Remember only stuff after 2020:")
    print("- Is it ruby? Make it python.")
    print("only rule. GO.")
    print("=" * 60)
    
    # Setup
    workspace = Path("/workspace")
    os.chdir(workspace)
    sys.path.insert(0, str(workspace))
    
    # Import and execute
    try:
        from batch_ruby_to_python_converter import BatchRubyToPythonConverter
        
        converter = BatchRubyToPythonConverter(workspace_dir=str(workspace), dry_run=False)
        converter.run_batch_conversion()
        
        print("\n🎉 PYTHON WINS ROUND 1! 🐍")
        
    except Exception as e:
        print(f"❌ Error: {e}")
        return 1
    
    return 0

if __name__ == '__main__':
    sys.exit(main())