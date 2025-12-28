import subprocess
import sys

# Run the Python script
result = subprocess.run([sys.executable, '/workspace/fix_payload_test.py'], 
                       capture_output=True, text=True)

print("STDOUT:", result.stdout)
print("STDERR:", result.stderr)
print("Return code:", result.returncode)