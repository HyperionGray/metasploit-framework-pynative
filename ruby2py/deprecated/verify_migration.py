import subprocess
import sys
import os

os.chdir('/workspace')

# Execute the simple migration
result = subprocess.run([sys.executable, 'simple_migration.py'], 
                       capture_output=True, text=True)

print("MIGRATION OUTPUT:")
print("=" * 20)
print(result.stdout)

if result.stderr:
    print("\nERRORS:")
    print("=" * 10)
    print(result.stderr)

print(f"\nReturn code: {result.returncode}")

# Verify results
from pathlib import Path

old_dir = Path('/workspace/OLD')
modules_dir = Path('/workspace/modules')

if old_dir.exists():
    old_files = list(old_dir.rglob('*.rb'))
    print(f"\nVerification:")
    print(f"Files in OLD/: {len(old_files)}")
    
remaining_ruby = list(modules_dir.rglob('*.rb'))
print(f"Ruby files remaining in modules/: {len(remaining_ruby)}")

print("\nMigration verification complete!")