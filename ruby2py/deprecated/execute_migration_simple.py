#!/usr/bin/env python3

import os
import sys
import subprocess
from pathlib import Path

# Change to workspace directory
os.chdir('/workspace')

print("Ruby to Python Migration Executor")
print("=" * 40)

# First, let's do a quick analysis
print("Step 1: Quick Analysis")
print("-" * 20)

workspace = Path('/workspace')
modules_dir = workspace / 'modules'

if modules_dir.exists():
    ruby_files = list(modules_dir.rglob('*.rb'))
    python_files = list(modules_dir.rglob('*.py'))
    
    print(f"Ruby files in modules/: {len(ruby_files)}")
    print(f"Python files in modules/: {len(python_files)}")
    
    # Show some Ruby files
    if ruby_files:
        print("\nSample Ruby files found:")
        for i, rb_file in enumerate(ruby_files[:5]):
            rel_path = rb_file.relative_to(workspace)
            print(f"  {rel_path}")
        if len(ruby_files) > 5:
            print(f"  ... and {len(ruby_files) - 5} more")
else:
    print("modules/ directory not found!")
    sys.exit(1)

# Check if migration tools exist
migration_script = workspace / 'tools/migration/migrate_ruby_to_python.py'
discovery_script = workspace / 'tools/dev/discover_post_2020_exploits.py'

print(f"\nMigration tools status:")
print(f"  Migration script exists: {migration_script.exists()}")
print(f"  Discovery script exists: {discovery_script.exists()}")

if not migration_script.exists():
    print("Migration script not found! Cannot proceed.")
    sys.exit(1)

# Step 2: Modify the migration script to use OLD instead of legacy
print(f"\nStep 2: Modifying Migration Script")
print("-" * 35)

try:
    # Read the migration script
    with open(migration_script, 'r') as f:
        content = f.read()
    
    # Check if it already uses OLD
    if 'self.legacy_dir = self.workspace_dir / "OLD"' in content:
        print("Migration script already configured for OLD directory")
    else:
        # Create backup
        backup_path = migration_script.with_suffix('.py.backup')
        if not backup_path.exists():
            with open(backup_path, 'w') as f:
                f.write(content)
            print(f"Created backup: {backup_path.name}")
        
        # Replace legacy with OLD
        modified_content = content.replace(
            'self.legacy_dir = self.workspace_dir / "legacy"',
            'self.legacy_dir = self.workspace_dir / "OLD"'
        )
        modified_content = modified_content.replace(
            'f"Moved {rel_path} to legacy/{rel_path}"',
            'f"Moved {rel_path} to OLD/{rel_path}"'
        )
        modified_content = modified_content.replace(
            'f"[DRY RUN] Would move {rel_path} to legacy/{rel_path}"',
            'f"[DRY RUN] Would move {rel_path} to OLD/{rel_path}"'
        )
        modified_content = modified_content.replace(
            'print(f"\\nLegacy files location: {self.legacy_dir}")',
            'print(f"\\nOLD files location: {self.legacy_dir}")'
        )
        
        # Write modified script
        with open(migration_script, 'w') as f:
            f.write(modified_content)
        
        print("Migration script modified to use OLD directory")

except Exception as e:
    print(f"Error modifying migration script: {e}")
    sys.exit(1)

# Step 3: Run migration with dry-run first
print(f"\nStep 3: Running Migration (Dry Run)")
print("-" * 35)

try:
    cmd = [sys.executable, str(migration_script), '--dry-run', '--verbose']
    result = subprocess.run(cmd, capture_output=True, text=True)
    
    print("Dry run output:")
    if result.stdout:
        for line in result.stdout.split('\n'):
            if line.strip():
                print(f"  {line}")
    
    if result.stderr:
        print("Warnings/Errors:")
        for line in result.stderr.split('\n'):
            if line.strip():
                print(f"  {line}")
    
    if result.returncode != 0:
        print(f"Dry run failed with return code: {result.returncode}")
        sys.exit(1)
    
    print("Dry run completed successfully!")
    
except Exception as e:
    print(f"Error running dry run: {e}")
    sys.exit(1)

# Step 4: Ask user if they want to proceed
print(f"\nStep 4: Execute Actual Migration?")
print("-" * 35)

response = input("Proceed with actual migration? (y/N): ").strip().lower()

if response not in ['y', 'yes']:
    print("Migration cancelled by user.")
    sys.exit(0)

# Step 5: Run actual migration
print(f"\nStep 5: Running Actual Migration")
print("-" * 35)

try:
    cmd = [sys.executable, str(migration_script), '--verbose']
    result = subprocess.run(cmd, capture_output=True, text=True)
    
    print("Migration output:")
    if result.stdout:
        for line in result.stdout.split('\n'):
            if line.strip():
                print(f"  {line}")
    
    if result.stderr:
        print("Warnings/Errors:")
        for line in result.stderr.split('\n'):
            if line.strip():
                print(f"  {line}")
    
    if result.returncode == 0:
        print("\nMigration completed successfully!")
    else:
        print(f"\nMigration failed with return code: {result.returncode}")
        sys.exit(1)
    
except Exception as e:
    print(f"Error running migration: {e}")
    sys.exit(1)

# Step 6: Validate results
print(f"\nStep 6: Validating Results")
print("-" * 25)

old_dir = workspace / 'OLD'
if old_dir.exists():
    old_ruby_files = list(old_dir.rglob('*.rb'))
    print(f"Ruby files moved to OLD/: {len(old_ruby_files)}")
else:
    print("OLD directory not created")

# Count remaining Ruby files in modules
remaining_ruby = list(modules_dir.rglob('*.rb'))
print(f"Ruby files remaining in modules/: {len(remaining_ruby)}")

# Count Python files
current_python = list(modules_dir.rglob('*.py'))
print(f"Python files in modules/: {len(current_python)}")

print(f"\nMigration Summary:")
print(f"  Original Ruby files: {len(ruby_files)}")
print(f"  Files moved to OLD/: {len(old_ruby_files) if old_dir.exists() else 0}")
print(f"  Files remaining: {len(remaining_ruby)}")
print(f"  Python files: {len(current_python)}")

print(f"\nRuby to Python Migration - Round 5: COMPLETE!")
print("=" * 50)