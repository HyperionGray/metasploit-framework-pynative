#!/usr/bin/env python3

import os
import sys
import subprocess

def main():
    print("🥊 RUBY v PYTHON: ROUND 1: FIGHT! 🥊")
    print("=" * 60)
    print("Alright gang only 7.1k ruby files to go!! let's rock this potato!!!!!")
    print("Remember only stuff after 2020:")
    print("- Is it ruby? Make it python.")
    print("only rule. GO.")
    print("=" * 60)
    
    os.chdir('/workspace')
    
    # Execute the batch converter
    cmd = [sys.executable, 'batch_ruby_to_python_converter.py']
    
    print(f"\nExecuting: {' '.join(cmd)}")
    print("-" * 40)
    
    try:
        result = subprocess.run(cmd, check=False)
        
        if result.returncode == 0:
            print("\n🎉 PYTHON WINS ROUND 1! 🐍")
            print("✅ All post-2020 Ruby files converted successfully!")
        else:
            print(f"\n❌ Conversion failed with return code: {result.returncode}")
            
        return result.returncode
        
    except Exception as e:
        print(f"\n❌ Error executing conversion: {e}")
        return 1

if __name__ == '__main__':
    sys.exit(main())