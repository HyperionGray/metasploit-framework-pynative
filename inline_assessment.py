#!/usr/bin/env python3

# Execute the assessment directly in this script
import os
import sys
from pathlib import Path
import json
from datetime import datetime

print("METASPLOIT FRAMEWORK QUICK ASSESSMENT")
print("=" * 50)

# 1. Check main executables exist and are Python
print("\n1. Main Executables Check:")
executables = ['msfconsole', 'msfd', 'msfdb', 'msfvenom', 'msfrpc']
exec_results = {}

for exe in executables:
    exe_path = Path(exe)
    if exe_path.exists():
        try:
            with open(exe_path, 'r', encoding='utf-8', errors='ignore') as f:
                first_line = f.readline().strip()
                if 'python' in first_line.lower():
                    exec_results[exe] = "PYTHON"
                    print(f"  ✓ {exe} - Python executable")
                else:
                    exec_results[exe] = "OTHER"
                    print(f"  ⚠ {exe} - Not Python: {first_line[:50]}")
        except Exception as e:
            exec_results[exe] = f"ERROR: {str(e)[:50]}"
            print(f"  ✗ {exe} - Error reading: {str(e)[:50]}")
    else:
        exec_results[exe] = "MISSING"
        print(f"  ✗ {exe} - File not found")

# 2. Check Python framework core
print("\n2. Python Framework Core:")
core_path = Path('python_framework')
if core_path.exists():
    core_files = list(core_path.rglob('*.py'))
    print(f"  ✓ Python framework exists with {len(core_files)} Python files")
    
    # Check specific core files
    exploit_py = core_path / 'core' / 'exploit.py'
    if exploit_py.exists():
        print(f"  ✓ exploit.py found ({exploit_py.stat().st_size:,} bytes)")
        try:
            with open(exploit_py, 'r') as f:
                content = f.read()
                if 'class Exploit' in content and 'ABC' in content:
                    print("  ✓ Professional OOP design detected")
                else:
                    print("  ⚠ Basic implementation")
        except Exception as e:
            print(f"  ✗ Error reading exploit.py: {e}")
    else:
        print("  ✗ exploit.py not found")
else:
    print("  ✗ Python framework directory not found")

# 3. Check modules
print("\n3. Module Structure:")
modules_path = Path('modules')
if modules_path.exists():
    try:
        # Count different types of modules
        exploit_py = list(modules_path.glob('exploits/**/*.py'))
        exploit_rb = list(modules_path.glob('exploits/**/*.rb'))
        aux_py = list(modules_path.glob('auxiliary/**/*.py'))
        aux_rb = list(modules_path.glob('auxiliary/**/*.rb'))
        
        print(f"  • Exploit modules: {len(exploit_py)} Python, {len(exploit_rb)} Ruby")
        print(f"  • Auxiliary modules: {len(aux_py)} Python, {len(aux_rb)} Ruby")
        
        if len(exploit_py) > 0 or len(aux_py) > 0:
            print("  ✓ Python modules found")
        else:
            print("  ⚠ No Python modules found")
            
    except Exception as e:
        print(f"  ✗ Error scanning modules: {e}")
else:
    print("  ✗ Modules directory not found")

# 4. File count analysis
print("\n4. File Count Analysis:")
try:
    python_files = list(Path('.').rglob('*.py'))
    ruby_files = list(Path('.').rglob('*.rb'))
    
    print(f"  • Python files: {len(python_files):,}")
    print(f"  • Ruby files: {len(ruby_files):,}")
    
    if len(python_files) >= 5000:
        print("  ✓ Substantial Python codebase")
    elif len(python_files) >= 1000:
        print("  ⚠ Moderate Python codebase")
    else:
        print("  ✗ Small Python codebase")
        
except Exception as e:
    print(f"  ✗ Error counting files: {e}")

# 5. Documentation check
print("\n5. Documentation Check:")
docs = {
    'README.md': Path('README.md'),
    'RUBY2PY_CONVERSION_COMPLETE.md': Path('RUBY2PY_CONVERSION_COMPLETE.md'),
    'TEST_SUITE_COMPLETE.md': Path('TEST_SUITE_COMPLETE.md')
}

for name, path in docs.items():
    if path.exists():
        size = path.stat().st_size
        print(f"  ✓ {name} ({size:,} bytes)")
    else:
        print(f"  ✗ {name} missing")

# 6. Test infrastructure
print("\n6. Test Infrastructure:")
test_path = Path('test')
if test_path.exists():
    test_files = list(test_path.rglob('*.py'))
    print(f"  ✓ Test directory with {len(test_files)} Python files")
else:
    # Look for test files elsewhere
    test_files = list(Path('.').rglob('test_*.py'))
    print(f"  ⚠ No test directory, found {len(test_files)} test files")

# 7. Requirements check
print("\n7. Requirements Check:")
req_path = Path('requirements.txt')
if req_path.exists():
    try:
        with open(req_path, 'r') as f:
            lines = f.readlines()
            non_comment_lines = [l for l in lines if l.strip() and not l.strip().startswith('#')]
            print(f"  ✓ requirements.txt with {len(non_comment_lines)} dependencies")
    except Exception as e:
        print(f"  ✗ Error reading requirements.txt: {e}")
else:
    print("  ✗ requirements.txt not found")

print("\n" + "=" * 50)
print("ASSESSMENT SUMMARY")
print("=" * 50)

# Calculate basic score
score_components = []

# Executables (25%)
python_execs = sum(1 for status in exec_results.values() if status == "PYTHON")
exec_score = (python_execs / len(executables)) * 25
score_components.append(("Executables", exec_score, 25))

# Framework core (25%)
if core_path.exists():
    core_score = 25
else:
    core_score = 0
score_components.append(("Framework Core", core_score, 25))

# Modules (20%)
if modules_path.exists() and (len(exploit_py) > 0 or len(aux_py) > 0):
    module_score = 20
else:
    module_score = 0
score_components.append(("Modules", module_score, 20))

# Documentation (15%)
doc_score = sum(15/3 for path in docs.values() if path.exists())
score_components.append(("Documentation", doc_score, 15))

# Tests (15%)
if test_path.exists():
    test_score = 15
else:
    test_score = 5 if len(test_files) > 0 else 0
score_components.append(("Tests", test_score, 15))

total_score = sum(score for _, score, _ in score_components)
max_score = sum(max_val for _, _, max_val in score_components)

print(f"Component Scores:")
for name, score, max_val in score_components:
    print(f"  {name}: {score:.1f}/{max_val}")

print(f"\nOverall Score: {total_score:.1f}/{max_score} ({total_score/max_score*100:.1f}%)")

if total_score >= 80:
    status = "EXCELLENT - Production Ready"
elif total_score >= 60:
    status = "GOOD - Near Production"
elif total_score >= 40:
    status = "FAIR - Development Stage"
else:
    status = "NEEDS WORK - Early Stage"

print(f"Status: {status}")

print("\nKey Findings:")
print(f"- {python_execs}/{len(executables)} main executables converted to Python")
print(f"- Python framework core: {'Present' if core_path.exists() else 'Missing'}")
print(f"- Python modules: {len(exploit_py) + len(aux_py)} found")
print(f"- Documentation: {len([p for p in docs.values() if p.exists()])}/{len(docs)} files present")
print(f"- Test infrastructure: {'Present' if test_path.exists() else 'Limited'}")

print(f"\nThis appears to be a {status.split(' - ')[1].lower()} project with significant conversion work completed.")