#!/usr/bin/env python3

import os
import sys
from pathlib import Path

# Change to workspace directory
os.chdir('/workspace')

print("Ruby to Python Migration - Round 5: FIGHT!")
print("=" * 50)

workspace = Path('/workspace')

# Step 1: Quick analysis
print("Step 1: Analyzing current state...")

modules_dir = workspace / 'modules'
if not modules_dir.exists():
    print("ERROR: modules/ directory not found!")
    sys.exit(1)

ruby_files = list(modules_dir.rglob('*.rb'))
python_files = list(modules_dir.rglob('*.py'))

print(f"Found {len(ruby_files)} Ruby files in modules/")
print(f"Found {len(python_files)} Python files in modules/")

if ruby_files:
    print("\nSample Ruby files:")
    for i, rb_file in enumerate(ruby_files[:5]):
        rel_path = rb_file.relative_to(workspace)
        print(f"  {rel_path}")
    if len(ruby_files) > 5:
        print(f"  ... and {len(ruby_files) - 5} more")

# Step 2: Check migration script
print(f"\nStep 2: Checking migration tools...")

migration_script = workspace / 'tools/migration/migrate_ruby_to_python.py'
if not migration_script.exists():
    print("ERROR: Migration script not found!")
    sys.exit(1)

print("Migration script found ✓")

# Step 3: Modify migration script to use OLD
print(f"\nStep 3: Configuring for OLD directory...")

try:
    with open(migration_script, 'r') as f:
        content = f.read()
    
    if 'self.legacy_dir = self.workspace_dir / "OLD"' in content:
        print("Already configured for OLD directory ✓")
    else:
        # Create backup
        backup_path = migration_script.with_suffix('.py.backup')
        if not backup_path.exists():
            with open(backup_path, 'w') as f:
                f.write(content)
            print(f"Created backup: {backup_path.name}")
        
        # Modify content
        modified = content.replace(
            'self.legacy_dir = self.workspace_dir / "legacy"',
            'self.legacy_dir = self.workspace_dir / "OLD"'
        )
        modified = modified.replace('"legacy/"', '"OLD/"')
        modified = modified.replace('to legacy/', 'to OLD/')
        modified = modified.replace('Legacy files location', 'OLD files location')
        
        with open(migration_script, 'w') as f:
            f.write(modified)
        
        print("Migration script configured for OLD directory ✓")

except Exception as e:
    print(f"ERROR modifying migration script: {e}")
    sys.exit(1)

print(f"\nReady to execute migration!")
print(f"This will:")
print(f"  - Move pre-2020 Ruby files to OLD/ directory")
print(f"  - Convert post-2020 Ruby files to Python")
print(f"  - Preserve directory structure")

response = input(f"\nProceed? (y/N): ").strip().lower()
if response not in ['y', 'yes']:
    print("Migration cancelled.")
    sys.exit(0)

# Step 4: Execute migration
print(f"\nStep 4: Executing migration...")

import subprocess

try:
    cmd = [sys.executable, str(migration_script), '--verbose']
    print(f"Running: {' '.join(cmd)}")
    
    # Run the migration
    process = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, 
                              universal_newlines=True, bufsize=1)
    
    # Print output in real-time
    for line in process.stdout:
        print(f"  {line.rstrip()}")
    
    process.wait()
    
    if process.returncode == 0:
        print("\nMigration completed successfully! ✓")
    else:
        print(f"\nMigration failed with return code: {process.returncode}")
        sys.exit(1)

except Exception as e:
    print(f"ERROR running migration: {e}")
    sys.exit(1)

# Step 5: Validate results
print(f"\nStep 5: Validating results...")

old_dir = workspace / 'OLD'
if old_dir.exists():
    old_files = list(old_dir.rglob('*.rb'))
    print(f"Files moved to OLD/: {len(old_files)} ✓")
    
    if old_files:
        print("Sample files in OLD/:")
        for i, old_file in enumerate(old_files[:3]):
            rel_path = old_file.relative_to(old_dir)
            print(f"  OLD/{rel_path}")
        if len(old_files) > 3:
            print(f"  ... and {len(old_files) - 3} more")
else:
    print("OLD directory not created")

# Check remaining files
remaining_ruby = list(modules_dir.rglob('*.rb'))
current_python = list(modules_dir.rglob('*.py'))

print(f"Ruby files remaining in modules/: {len(remaining_ruby)}")
print(f"Python files in modules/: {len(current_python)}")

print(f"\n" + "=" * 50)
print("RUBY TO PYTHON MIGRATION - ROUND 5: COMPLETE!")
print("=" * 50)
print(f"Summary:")
print(f"  Original Ruby files: {len(ruby_files)}")
print(f"  Moved to OLD/: {len(old_files) if old_dir.exists() else 0}")
print(f"  Remaining Ruby: {len(remaining_ruby)}")
print(f"  Total Python files: {len(current_python)}")
print(f"\nPre-2020 files are now in the OLD/ directory")
print(f"Post-2020 files have been converted to Python")
print("Migration successful! 🥊")