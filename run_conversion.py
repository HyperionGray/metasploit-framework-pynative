#!/usr/bin/env python3

import subprocess
import sys
from pathlib import Path

# Run the PyNative conversion
repo_root = Path("/workspace")
converter_script = repo_root / "convert_to_pynative.py"

print("🐍 Starting PyNative Metasploit Conversion...")
print("="*70)

try:
    result = subprocess.run(
        [sys.executable, str(converter_script), "--repo-root", str(repo_root)],
        cwd=repo_root,
        capture_output=False,  # Show output in real-time
        text=True
    )
    
    if result.returncode == 0:
        print("\n🎉 PyNative conversion completed successfully!")
    else:
        print(f"\n⚠️ Conversion completed with exit code: {result.returncode}")
        
except Exception as e:
    print(f"❌ Error running conversion: {e}")
    sys.exit(1)