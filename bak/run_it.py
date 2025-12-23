import subprocess
import sys
import os

os.chdir('/workspace')

# Execute the migration
result = subprocess.run([sys.executable, 'execute_migration_inline.py'])
print(f"\nMigration completed with return code: {result.returncode}")