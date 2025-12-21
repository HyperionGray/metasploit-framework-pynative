#!/usr/bin/env python3

import subprocess
import sys
import os
from pathlib import Path

def execute_round2():
    """Execute Round 2 migration process"""
    
    print("🐍🔥 ROUND 2: FIGHT! - EXECUTING MIGRATION 🔥🐍")
    print("=" * 60)
    print("Mission: Convert post-2020 Ruby to Python")
    print("         Move pre-2020 Ruby to legacy")
    print("         KILL ALL THE RUBY!")
    print("=" * 60)
    
    workspace = Path('/workspace')
    os.chdir(workspace)
    
    # Step 1: Quick inventory
    print("\n🔍 Step 1: Ruby file inventory...")
    try:
        subprocess.run([sys.executable, 'quick_check.py'], check=False)
    except Exception as e:
        print(f"Inventory error: {e}")
    
    # Step 2: Check if migration script exists and run it
    migration_script = workspace / 'tools/migration/migrate_ruby_to_python.py'
    
    if migration_script.exists():
        print(f"\n🚀 Step 2: Running migration script...")
        print(f"Script location: {migration_script}")
        
        try:
            # Run migration with verbose output
            result = subprocess.run([
                sys.executable, str(migration_script), 
                '--verbose', '--workspace', str(workspace)
            ], cwd=str(workspace), timeout=300)
            
            if result.returncode == 0:
                print("✅ Migration script completed successfully!")
            else:
                print(f"⚠️  Migration script returned code: {result.returncode}")
                
        except subprocess.TimeoutExpired:
            print("⚠️  Migration script timed out after 5 minutes")
        except Exception as e:
            print(f"❌ Migration script error: {e}")
    else:
        print(f"\n⚠️  Migration script not found at: {migration_script}")
        print("Available migration files:")
        for py_file in workspace.glob("*migration*.py"):
            print(f"  - {py_file}")
        for py_file in workspace.glob("*ruby*.py"):
            print(f"  - {py_file}")
    
    # Step 3: Run Ruby killer as backup
    print(f"\n🎯 Step 3: Final Ruby elimination...")
    ruby_killer = workspace / 'final_ruby_killer.py'
    
    if ruby_killer.exists():
        try:
            subprocess.run([sys.executable, str(ruby_killer)], 
                         cwd=str(workspace), check=False)
        except Exception as e:
            print(f"Ruby killer error: {e}")
    else:
        print("Ruby killer script not found")
    
    # Step 4: Final status
    print(f"\n📊 Step 4: Final status check...")
    
    # Count remaining Ruby files
    ruby_files = []
    for rb_file in workspace.rglob("*.rb"):
        if not any(skip in str(rb_file) for skip in ['legacy/', '.git/', 'spec/', 'test/']):
            ruby_files.append(rb_file)
    
    python_files = list(workspace.glob("modules/**/*.py"))
    
    print(f"Remaining Ruby files (non-legacy): {len(ruby_files)}")
    print(f"Python modules: {len(python_files)}")
    
    # Show some examples
    if ruby_files:
        print("Sample remaining Ruby files:")
        for rb_file in ruby_files[:5]:
            rel_path = rb_file.relative_to(workspace)
            print(f"  - {rel_path}")
    
    print("\n" + "=" * 60)
    print("🎉 ROUND 2 EXECUTION COMPLETE!")
    
    if len(ruby_files) == 0:
        print("🏆 PERFECT! NO RUBY FILES REMAIN!")
        print("🐍 PYTHON TOTAL VICTORY! 🐍")
    elif len(ruby_files) < 10:
        print(f"🎯 EXCELLENT! Only {len(ruby_files)} Ruby files remain!")
        print("🐍 PYTHON DOMINANCE ACHIEVED! 🐍")
    else:
        print(f"⚠️  {len(ruby_files)} Ruby files still remain")
        print("🐍 PYTHON PROGRESS MADE! 🐍")
    
    print("=" * 60)
    
    return len(ruby_files) == 0

if __name__ == '__main__':
    success = execute_round2()
    
    if success:
        print("\n🚀 MISSION ACCOMPLISHED!")
        print("Ruby has been completely eliminated!")
    else:
        print("\n🎯 MISSION PROGRESS!")
        print("Ruby reduction achieved!")
    
    sys.exit(0)