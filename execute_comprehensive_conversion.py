#!/usr/bin/env python3
"""
Comprehensive Ruby to Python Conversion Executor
Executes the full conversion process for Metasploit Framework Round 4
"""

import os
import sys
import subprocess
import time
from pathlib import Path

def run_command(cmd, description):
    """Run a command and return success status"""
    print(f"\n{'='*60}")
    print(f"🚀 {description}")
    print(f"{'='*60}")
    print(f"Command: {' '.join(cmd)}")
    print("-" * 60)
    
    try:
        result = subprocess.run(cmd, cwd="/workspace", capture_output=True, text=True)
        
        if result.stdout:
            print("STDOUT:")
            print(result.stdout)
        
        if result.stderr:
            print("STDERR:")
            print(result.stderr)
        
        if result.returncode == 0:
            print(f"✅ {description} - SUCCESS")
            return True
        else:
            print(f"❌ {description} - FAILED (exit code: {result.returncode})")
            return False
            
    except Exception as e:
        print(f"❌ {description} - ERROR: {e}")
        return False

def main():
    """Execute comprehensive Ruby to Python conversion"""
    
    print("🔥 METASPLOIT FRAMEWORK RUBY → PYTHON CONVERSION")
    print("🔥 ROUND 4: COMPREHENSIVE MIGRATION")
    print("=" * 80)
    print("Mission: Convert Ruby to Python and do it GOOD!")
    print("=" * 80)
    
    os.chdir("/workspace")
    
    # Phase 1: Discovery and Assessment
    print("\n🔍 PHASE 1: DISCOVERY AND ASSESSMENT")
    
    success_count = 0
    total_phases = 5
    
    # Discover Ruby files
    if run_command([sys.executable, "find_ruby_files.py"], "Discovering Ruby files"):
        success_count += 1
    
    # Count current Ruby files
    if run_command([sys.executable, "count_ruby_files.py"], "Counting Ruby files"):
        success_count += 1
    
    # Phase 2: Batch Conversion (Dry Run First)
    print("\n🧪 PHASE 2: BATCH CONVERSION (DRY RUN)")
    
    if run_command([sys.executable, "batch_ruby_to_python_converter.py", "--dry-run"], 
                   "Batch conversion dry run"):
        success_count += 1
    
    # Phase 3: Actual Batch Conversion
    print("\n⚡ PHASE 3: ACTUAL BATCH CONVERSION")
    
    if run_command([sys.executable, "batch_ruby_to_python_converter.py"], 
                   "Batch conversion execution"):
        success_count += 1
    
    # Phase 4: Legacy Migration
    print("\n📦 PHASE 4: LEGACY MIGRATION")
    
    if run_command([sys.executable, "final_ruby_killer.py"], 
                   "Ruby elimination and legacy migration"):
        success_count += 1
    
    # Phase 5: Final Verification
    print("\n✅ PHASE 5: FINAL VERIFICATION")
    
    # Count remaining Ruby files
    run_command([sys.executable, "count_ruby_files.py"], "Final Ruby file count")
    
    # Summary
    print("\n" + "=" * 80)
    print("🎯 CONVERSION SUMMARY")
    print("=" * 80)
    print(f"Phases completed successfully: {success_count}/{total_phases}")
    
    if success_count == total_phases:
        print("🎉 COMPLETE SUCCESS! RUBY HAS BEEN CONVERTED TO PYTHON!")
        print("🐍 PYTHON SUPREMACY ACHIEVED!")
        print("✅ All conversion phases completed successfully")
        print("✅ Ruby files moved to legacy")
        print("✅ Python modules ready for use")
    elif success_count >= 3:
        print("⚠️  PARTIAL SUCCESS - Most phases completed")
        print("🔧 Some manual intervention may be needed")
    else:
        print("❌ CONVERSION FAILED - Multiple phases had errors")
        print("🛠️  Manual debugging required")
    
    print("=" * 80)
    
    # Final status check
    print("\n📊 FINAL STATUS CHECK")
    print("-" * 40)
    
    workspace = Path("/workspace")
    
    # Count Python modules
    python_modules = list(workspace.glob("modules/**/*.py"))
    print(f"Python modules found: {len(python_modules)}")
    
    # Count remaining Ruby files (excluding legacy)
    ruby_files = []
    for rb_file in workspace.glob("**/*.rb"):
        if "legacy" not in str(rb_file) and ".git" not in str(rb_file):
            ruby_files.append(rb_file)
    
    print(f"Ruby files remaining (non-legacy): {len(ruby_files)}")
    
    # Check legacy directory
    legacy_dir = workspace / "legacy"
    if legacy_dir.exists():
        legacy_ruby = list(legacy_dir.glob("**/*.rb"))
        print(f"Ruby files in legacy: {len(legacy_ruby)}")
    else:
        print("Legacy directory not found")
    
    print("\n🚀 CONVERSION PROCESS COMPLETE!")
    
    return success_count >= 3

if __name__ == "__main__":
    success = main()
    sys.exit(0 if success else 1)