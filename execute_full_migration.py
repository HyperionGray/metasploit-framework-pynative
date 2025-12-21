import subprocess
import sys
import os

os.chdir('/workspace')

# Run setup to see current state
print("Running migration setup...")
result = subprocess.run([sys.executable, 'migration_setup.py'], capture_output=True, text=True)
print(result.stdout)
if result.stderr:
    print("STDERR:", result.stderr)

# Now run the actual migration
print("\n" + "="*50)
print("Running actual migration...")
result = subprocess.run([sys.executable, 'final_migration_exec.py'], capture_output=True, text=True)
print(result.stdout)
if result.stderr:
    print("STDERR:", result.stderr)

print(f"Migration return code: {result.returncode}")