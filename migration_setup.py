#!/usr/bin/env python3

# Simple migration execution
import os
import sys
from pathlib import Path

os.chdir('/workspace')

print("Ruby to Python Migration - Round 5: FIGHT!")
print("=" * 50)

# Check workspace structure
workspace = Path('/workspace')
modules_dir = workspace / 'modules'

print(f"Workspace: {workspace}")
print(f"Modules dir exists: {modules_dir.exists()}")

if modules_dir.exists():
    ruby_files = list(modules_dir.rglob('*.rb'))
    python_files = list(modules_dir.rglob('*.py'))
    
    print(f"Ruby files found: {len(ruby_files)}")
    print(f"Python files found: {len(python_files)}")
    
    if ruby_files:
        print("\nFirst 3 Ruby files:")
        for rb_file in ruby_files[:3]:
            rel_path = rb_file.relative_to(workspace)
            print(f"  {rel_path}")
    
    # Create OLD directory
    old_dir = workspace / 'OLD'
    old_dir.mkdir(exist_ok=True)
    print(f"\nOLD directory created: {old_dir}")
    
    print(f"\nReady to process {len(ruby_files)} Ruby files")
    print("Migration setup complete!")
else:
    print("ERROR: modules/ directory not found!")
    print("Available directories:")
    for item in workspace.iterdir():
        if item.is_dir():
            print(f"  {item.name}")

print("\nSetup phase completed.")