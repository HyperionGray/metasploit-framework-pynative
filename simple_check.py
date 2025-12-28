#!/usr/bin/env python3

# Simple inline assessment
import os
from pathlib import Path

print("METASPLOIT FRAMEWORK ASSESSMENT")
print("=" * 40)

# Check executables
print("\n1. Main Executables:")
for exe in ['msfconsole', 'msfd', 'msfdb', 'msfvenom']:
    if Path(exe).exists():
        print(f"  ✓ {exe} exists")
    else:
        print(f"  ✗ {exe} missing")

# Check framework
print("\n2. Framework Structure:")
if Path('python_framework').exists():
    print("  ✓ python_framework/ exists")
else:
    print("  ✗ python_framework/ missing")

if Path('modules').exists():
    print("  ✓ modules/ exists")
else:
    print("  ✗ modules/ missing")

# Count files
print("\n3. File Counts:")
try:
    py_files = len(list(Path('.').rglob('*.py')))
    rb_files = len(list(Path('.').rglob('*.rb')))
    print(f"  • Python files: {py_files:,}")
    print(f"  • Ruby files: {rb_files:,}")
except:
    print("  ✗ Error counting files")

# Check docs
print("\n4. Documentation:")
for doc in ['README.md', 'RUBY2PY_CONVERSION_COMPLETE.md']:
    if Path(doc).exists():
        size = Path(doc).stat().st_size
        print(f"  ✓ {doc} ({size:,} bytes)")
    else:
        print(f"  ✗ {doc} missing")

print("\n" + "=" * 40)
print("Assessment complete - see results above")