import subprocess
import sys

result = subprocess.run([sys.executable, '/workspace/final_ruby_killer.py'], 
                       capture_output=True, text=True)
print(result.stdout)
if result.stderr:
    print("STDERR:", result.stderr)
print("Return code:", result.returncode)