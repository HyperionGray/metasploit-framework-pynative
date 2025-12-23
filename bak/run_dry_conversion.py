#!/usr/bin/env python3
import subprocess
import sys
from pathlib import Path

# Run the batch converter in dry-run mode first
workspace = Path("/workspace")
converter_path = workspace / "batch_ruby_to_python_converter.py"

print("Running Ruby to Python conversion in DRY-RUN mode...")
print("="*60)

try:
    result = subprocess.run([
        sys.executable, str(converter_path), "--dry-run"
    ], cwd=workspace, capture_output=True, text=True)
    
    print("STDOUT:")
    print(result.stdout)
    
    if result.stderr:
        print("\nSTDERR:")
        print(result.stderr)
    
    print(f"\nReturn code: {result.returncode}")
    
except Exception as e:
    print(f"Error running converter: {e}")