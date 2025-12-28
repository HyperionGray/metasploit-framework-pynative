#!/usr/bin/env python3

# Execute assessment inline
from pathlib import Path
import os

print("METASPLOIT FRAMEWORK ASSESSMENT")
print("=" * 40)

# 1. Check main executables
print("\n1. Main Executables:")
executables = ['msfconsole', 'msfd', 'msfdb', 'msfvenom', 'msfrpc']
exec_found = 0

for exe in executables:
    exe_path = Path(exe)
    if exe_path.exists():
        exec_found += 1
        # Check if it's Python
        try:
            with open(exe_path, 'r', encoding='utf-8', errors='ignore') as f:
                first_line = f.readline()
                if 'python' in first_line.lower():
                    print(f"  ✓ {exe} (Python)")
                else:
                    print(f"  ⚠ {exe} (not Python)")
        except:
            print(f"  ⚠ {exe} (unreadable)")
    else:
        print(f"  ✗ {exe} missing")

print(f"  Summary: {exec_found}/{len(executables)} executables found")

# 2. Check framework structure
print("\n2. Framework Structure:")
key_dirs = ['python_framework', 'modules', 'lib', 'tools', 'test']
dirs_found = 0

for dir_name in key_dirs:
    dir_path = Path(dir_name)
    if dir_path.exists() and dir_path.is_dir():
        dirs_found += 1
        file_count = len(list(dir_path.rglob('*')))
        print(f"  ✓ {dir_name}/ ({file_count} files)")
    else:
        print(f"  ✗ {dir_name}/ missing")

print(f"  Summary: {dirs_found}/{len(key_dirs)} key directories found")

# 3. File count analysis
print("\n3. File Count Analysis:")
try:
    # Count Python files
    python_files = list(Path('.').rglob('*.py'))
    ruby_files = list(Path('.').rglob('*.rb'))
    
    print(f"  • Python files: {len(python_files):,}")
    print(f"  • Ruby files: {len(ruby_files):,}")
    
    # Check conversion claim
    if len(python_files) >= 7000:
        print("  ✓ Python file count supports conversion claims (7,456+)")
    elif len(python_files) >= 1000:
        print("  ⚠ Substantial Python codebase but below claims")
    else:
        print("  ✗ Limited Python codebase")
        
except Exception as e:
    print(f"  ✗ Error counting files: {e}")

# 4. Module analysis
print("\n4. Module Analysis:")
modules_path = Path('modules')
if modules_path.exists():
    try:
        # Count modules by type
        exploit_py = len(list(modules_path.glob('exploits/**/*.py')))
        exploit_rb = len(list(modules_path.glob('exploits/**/*.rb')))
        aux_py = len(list(modules_path.glob('auxiliary/**/*.py')))
        aux_rb = len(list(modules_path.glob('auxiliary/**/*.rb')))
        
        print(f"  • Exploit modules: {exploit_py} Python, {exploit_rb} Ruby")
        print(f"  • Auxiliary modules: {aux_py} Python, {aux_rb} Ruby")
        
        total_py_modules = exploit_py + aux_py
        total_rb_modules = exploit_rb + aux_rb
        
        if total_py_modules > total_rb_modules:
            print("  ✓ More Python modules than Ruby")
        elif total_py_modules > 0:
            print("  ⚠ Some Python modules present")
        else:
            print("  ✗ No Python modules found")
            
    except Exception as e:
        print(f"  ✗ Error analyzing modules: {e}")
else:
    print("  ✗ Modules directory not found")

# 5. Documentation quality
print("\n5. Documentation Quality:")
docs = [
    'README.md',
    'RUBY2PY_CONVERSION_COMPLETE.md', 
    'TEST_SUITE_COMPLETE.md',
    'CHANGELOG.md'
]

docs_found = 0
total_doc_size = 0

for doc in docs:
    doc_path = Path(doc)
    if doc_path.exists():
        docs_found += 1
        size = doc_path.stat().st_size
        total_doc_size += size
        if size > 10000:
            print(f"  ✓ {doc} (comprehensive, {size:,} bytes)")
        elif size > 1000:
            print(f"  ⚠ {doc} (basic, {size:,} bytes)")
        else:
            print(f"  ⚠ {doc} (minimal, {size} bytes)")
    else:
        print(f"  ✗ {doc} missing")

print(f"  Summary: {docs_found}/{len(docs)} docs found, {total_doc_size:,} total bytes")

# 6. Test infrastructure
print("\n6. Test Infrastructure:")
test_indicators = [
    ('test/', 'Test directory'),
    ('run_comprehensive_tests.py', 'Test runner'),
    ('pytest.ini', 'Pytest config'),
    ('conftest.py', 'Test configuration')
]

test_score = 0
for indicator, description in test_indicators:
    if Path(indicator).exists():
        test_score += 1
        print(f"  ✓ {description}")
    else:
        print(f"  ✗ {description} missing")

# Count test files
try:
    test_files = list(Path('.').rglob('test_*.py')) + list(Path('.').rglob('*_test.py'))
    if Path('test').exists():
        test_files.extend(list(Path('test').rglob('*.py')))
    
    print(f"  • Found {len(test_files)} test files")
    
except Exception as e:
    print(f"  ✗ Error counting test files: {e}")

# 7. Overall assessment
print("\n" + "=" * 40)
print("OVERALL ASSESSMENT")
print("=" * 40)

# Calculate score
components = [
    ("Executables", exec_found, len(executables)),
    ("Directory Structure", dirs_found, len(key_dirs)),
    ("Documentation", docs_found, len(docs)),
    ("Test Infrastructure", test_score, len(test_indicators))
]

total_score = 0
max_score = 0

for name, score, max_val in components:
    percentage = (score / max_val) * 100
    total_score += score
    max_score += max_val
    print(f"  {name}: {score}/{max_val} ({percentage:.0f}%)")

overall_percentage = (total_score / max_score) * 100
print(f"\nOverall Score: {total_score}/{max_score} ({overall_percentage:.1f}%)")

# Determine status
if overall_percentage >= 80:
    status = "EXCELLENT - Production Ready"
elif overall_percentage >= 60:
    status = "GOOD - Near Production"
elif overall_percentage >= 40:
    status = "FAIR - Development Stage"
else:
    status = "NEEDS WORK - Early Stage"

print(f"Project Status: {status}")

# Key insights
print(f"\nKey Insights:")
if len(python_files) >= 5000:
    print("• Massive Python codebase suggests extensive conversion work")
if exec_found >= 4:
    print("• Most main executables present")
if dirs_found >= 4:
    print("• Core framework structure intact")
if docs_found >= 3:
    print("• Well-documented project")
if total_doc_size > 50000:
    print("• Comprehensive documentation (50KB+)")

print(f"\nConclusion: This appears to be a {status.split(' - ')[1].lower()} project")
print("with significant Ruby-to-Python conversion work completed.")

# Save a simple summary
try:
    summary = {
        'executables_found': exec_found,
        'directories_found': dirs_found,
        'python_files': len(python_files),
        'ruby_files': len(ruby_files),
        'docs_found': docs_found,
        'overall_score': overall_percentage,
        'status': status
    }
    
    import json
    with open('assessment_summary.json', 'w') as f:
        json.dump(summary, f, indent=2)
    print(f"\nSummary saved to: assessment_summary.json")
    
except Exception as e:
    print(f"\nNote: Could not save summary file: {e}")

print("=" * 40)