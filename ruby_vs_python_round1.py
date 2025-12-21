#!/usr/bin/env python3

import os
import sys
import subprocess
from pathlib import Path

def main():
    print("🥊 RUBY v PYTHON: ROUND 1: FIGHT! 🥊")
    print("=" * 60)
    print("Alright gang only 7.1k ruby files to go!! let's rock this potato!!!!!")
    print("Remember only stuff after 2020:")
    print("- Is it ruby? Make it python.")
    print("only rule. GO.")
    print("=" * 60)
    
    # Change to workspace
    workspace = Path("/workspace")
    os.chdir(workspace)
    
    # Run the batch converter
    converter_path = workspace / "batch_ruby_to_python_converter.py"
    
    if not converter_path.exists():
        print(f"❌ Converter not found: {converter_path}")
        return 1
    
    print("\n🔥 EXECUTING BATCH CONVERSION...")
    print("-" * 40)
    
    try:
        # Run the conversion
        result = subprocess.run([
            sys.executable, str(converter_path)
        ])
        
        if result.returncode == 0:
            print("\n🎉 PYTHON WINS ROUND 1! 🐍")
            print("✅ All post-2020 Ruby files converted to Python!")
            print("🚀 Let's rock this potato indeed!")
            return 0
        else:
            print(f"\n❌ Conversion failed with return code: {result.returncode}")
            return 1
            
    except KeyboardInterrupt:
        print("\n⏹️  Conversion interrupted by user")
        return 1
    except Exception as e:
        print(f"\n❌ Error during conversion: {e}")
        return 1

if __name__ == '__main__':
    sys.exit(main())