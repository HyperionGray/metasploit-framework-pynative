#!/usr/bin/env python3

import os
import shutil
from pathlib import Path

def kill_ruby_now():
    """Immediately execute Ruby elimination"""
    
    print("🔥 IMMEDIATE RUBY ELIMINATION 🔥")
    print("Request: 'kill that ruby. And move to python lets go!!'")
    print("=" * 60)
    
    workspace = Path('/workspace')
    legacy_dir = workspace / 'legacy'
    
    # Ensure we're in the right directory
    os.chdir(workspace)
    
    # Create legacy directory structure
    legacy_dir.mkdir(exist_ok=True)
    for subdir in ['modules', 'lib', 'tools', 'scripts', 'external', 'plugins']:
        (legacy_dir / subdir).mkdir(exist_ok=True)
    
    print("✅ Legacy directory structure created")
    
    # Find all Ruby files in the workspace
    ruby_files = []
    
    # Search in key directories
    search_dirs = ['modules', 'lib', 'tools', 'scripts', 'plugins', 'external']
    
    for search_dir in search_dirs:
        dir_path = workspace / search_dir
        if dir_path.exists():
            for rb_file in dir_path.rglob('*.rb'):
                # Skip if already in legacy
                if 'legacy' not in rb_file.parts:
                    ruby_files.append(rb_file)
    
    print(f"📊 Found {len(ruby_files)} Ruby files to eliminate")
    
    # Execute the elimination
    moved_count = 0
    error_count = 0
    
    for rb_file in ruby_files:
        try:
            # Calculate relative path from workspace
            rel_path = rb_file.relative_to(workspace)
            
            # Create target path in legacy
            legacy_path = legacy_dir / rel_path
            
            # Ensure parent directory exists
            legacy_path.parent.mkdir(parents=True, exist_ok=True)
            
            # Move the file
            shutil.move(str(rb_file), str(legacy_path))
            moved_count += 1
            
            # Show progress for first few files
            if moved_count <= 20:
                print(f"✅ Eliminated: {rel_path}")
            elif moved_count == 21:
                print("... (continuing elimination process)")
                
        except Exception as e:
            error_count += 1
            print(f"❌ Failed to eliminate {rb_file}: {e}")
    
    # Final verification
    remaining_ruby = []
    for search_dir in search_dirs:
        dir_path = workspace / search_dir
        if dir_path.exists():
            for rb_file in dir_path.rglob('*.rb'):
                if 'legacy' not in rb_file.parts:
                    remaining_ruby.append(rb_file)
    
    # Results
    print("\n" + "=" * 60)
    print("🎯 RUBY ELIMINATION RESULTS")
    print("=" * 60)
    print(f"Ruby files eliminated: {moved_count}")
    print(f"Errors encountered: {error_count}")
    print(f"Remaining Ruby files: {len(remaining_ruby)}")
    print("=" * 60)
    
    if len(remaining_ruby) == 0:
        print("🎉 COMPLETE SUCCESS!")
        print("🔥 ALL RUBY FILES HAVE BEEN KILLED!")
        print("🐍 PYTHON IS NOW THE SUPREME LANGUAGE!")
        print("✅ Ruby legacy preserved in legacy/ directory")
        print("✅ Python framework is ready for action")
        
        # Show Python framework status
        python_framework = workspace / 'python_framework'
        if python_framework.exists():
            print("✅ Python framework detected and ready")
            core_files = list(python_framework.rglob('*.py'))
            print(f"✅ {len(core_files)} Python framework files available")
        
        return True
    else:
        print("⚠️  PARTIAL SUCCESS - Some Ruby files remain:")
        for f in remaining_ruby[:10]:
            print(f"  - {f.relative_to(workspace)}")
        return False

# Execute immediately
if __name__ == '__main__':
    success = kill_ruby_now()
    
    if success:
        print("\n🚀 MISSION ACCOMPLISHED!")
        print("Ruby has been successfully killed!")
        print("Welcome to the Python era! 🐍")
    else:
        print("\n⚠️  Mission partially completed")
        print("Some Ruby resistance remains...")

# Run the function
kill_ruby_now()