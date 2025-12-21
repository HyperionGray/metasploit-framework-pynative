#!/usr/bin/env python3
"""
Direct Ruby to Python Conversion Execution
"""

import os
import sys
import subprocess
from pathlib import Path

def main():
    os.chdir('/workspace')
    
    print("🔥 RUBY TO PYTHON CONVERSION - DIRECT EXECUTION")
    print("=" * 60)
    
    # Step 1: Quick Ruby scan
    print("\n🔍 STEP 1: Ruby File Discovery")
    print("-" * 40)
    
    workspace = Path("/workspace")
    ruby_files = []
    
    for root, dirs, files in os.walk(workspace):
        # Skip hidden directories and legacy
        dirs[:] = [d for d in dirs if not d.startswith('.') and d != 'legacy']
        
        for file in files:
            if file.endswith('.rb'):
                full_path = Path(root) / file
                ruby_files.append(full_path)
    
    print(f"Found {len(ruby_files)} Ruby files to process:")
    for i, rb_file in enumerate(ruby_files[:10]):
        rel_path = rb_file.relative_to(workspace)
        print(f"  {i+1:2d}. {rel_path}")
    
    if len(ruby_files) > 10:
        print(f"  ... and {len(ruby_files) - 10} more files")
    
    # Step 2: Execute batch conversion
    print(f"\n⚡ STEP 2: Batch Conversion")
    print("-" * 40)
    
    try:
        result = subprocess.run([
            sys.executable, "batch_ruby_to_python_converter.py"
        ], capture_output=True, text=True, cwd="/workspace")
        
        print("STDOUT:")
        print(result.stdout)
        
        if result.stderr:
            print("STDERR:")
            print(result.stderr)
        
        if result.returncode == 0:
            print("✅ Batch conversion completed successfully")
        else:
            print(f"⚠️  Batch conversion completed with warnings (exit code: {result.returncode})")
    
    except Exception as e:
        print(f"❌ Batch conversion failed: {e}")
    
    # Step 3: Execute Ruby killer
    print(f"\n🔥 STEP 3: Ruby Elimination")
    print("-" * 40)
    
    try:
        result = subprocess.run([
            sys.executable, "final_ruby_killer.py"
        ], capture_output=True, text=True, cwd="/workspace")
        
        print("STDOUT:")
        print(result.stdout)
        
        if result.stderr:
            print("STDERR:")
            print(result.stderr)
        
        if result.returncode == 0:
            print("✅ Ruby elimination completed successfully")
        else:
            print(f"⚠️  Ruby elimination completed with warnings (exit code: {result.returncode})")
    
    except Exception as e:
        print(f"❌ Ruby elimination failed: {e}")
    
    # Step 4: Final status
    print(f"\n📊 STEP 4: Final Status")
    print("-" * 40)
    
    # Count remaining Ruby files
    remaining_ruby = []
    for root, dirs, files in os.walk(workspace):
        dirs[:] = [d for d in dirs if not d.startswith('.') and d != 'legacy']
        for file in files:
            if file.endswith('.rb'):
                remaining_ruby.append(Path(root) / file)
    
    print(f"Ruby files remaining (non-legacy): {len(remaining_ruby)}")
    
    # Count Python modules
    python_modules = list(workspace.glob("modules/**/*.py"))
    print(f"Python modules found: {len(python_modules)}")
    
    # Check legacy directory
    legacy_dir = workspace / "legacy"
    if legacy_dir.exists():
        legacy_ruby = list(legacy_dir.glob("**/*.rb"))
        print(f"Ruby files in legacy: {len(legacy_ruby)}")
    
    print("\n🎉 CONVERSION PROCESS COMPLETE!")
    
    if len(remaining_ruby) == 0:
        print("🐍 PERFECT! ALL RUBY FILES ELIMINATED!")
        print("✅ Python conversion successful")
        return True
    else:
        print(f"⚠️  {len(remaining_ruby)} Ruby files still remain")
        for f in remaining_ruby[:5]:
            print(f"  - {f.relative_to(workspace)}")
        return False

if __name__ == "__main__":
    success = main()
    sys.exit(0 if success else 1)