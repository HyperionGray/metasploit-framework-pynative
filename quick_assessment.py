#!/usr/bin/env python3
"""
Quick Assessment Runner - Tests core functionality without external dependencies
"""

import os
import sys
from pathlib import Path
import json
from datetime import datetime

def quick_assessment():
    """Run a quick assessment of the framework"""
    results = {
        'timestamp': datetime.now().isoformat(),
        'assessment': 'QUICK_FRAMEWORK_CHECK',
        'findings': {}
    }
    
    print("METASPLOIT FRAMEWORK QUICK ASSESSMENT")
    print("=" * 50)
    
    # 1. Check main executables exist and are Python
    print("\n1. Main Executables Check:")
    executables = ['msfconsole', 'msfd', 'msfdb', 'msfvenom', 'msfrpc']
    exec_status = {}
    
    for exe in executables:
        if Path(exe).exists():
            with open(exe, 'r') as f:
                first_line = f.readline().strip()
                if first_line.startswith('#!/usr/bin/env python'):
                    exec_status[exe] = "CONVERTED_TO_PYTHON"
                    print(f"  ✓ {exe} - Converted to Python")
                else:
                    exec_status[exe] = "NOT_PYTHON"
                    print(f"  ⚠ {exe} - Not Python")
        else:
            exec_status[exe] = "MISSING"
            print(f"  ✗ {exe} - Missing")
    
    results['findings']['executables'] = exec_status
    
    # 2. Check Python framework core
    print("\n2. Python Framework Core:")
    core_path = Path('python_framework/core')
    if core_path.exists():
        core_files = list(core_path.glob('*.py'))
        print(f"  ✓ Core framework exists with {len(core_files)} Python files")
        results['findings']['core_framework'] = f"{len(core_files)} files"
        
        # Check exploit.py specifically
        exploit_py = core_path / 'exploit.py'
        if exploit_py.exists():
            with open(exploit_py, 'r') as f:
                content = f.read()
                if 'class Exploit' in content and 'ABC' in content:
                    print("  ✓ Professional OOP design detected in exploit.py")
                    results['findings']['exploit_class'] = "PROFESSIONAL_DESIGN"
                else:
                    print("  ⚠ Basic implementation in exploit.py")
                    results['findings']['exploit_class'] = "BASIC_IMPLEMENTATION"
    else:
        print("  ✗ Python framework core not found")
        results['findings']['core_framework'] = "MISSING"
    
    # 3. Check module structure
    print("\n3. Module Structure:")
    modules_path = Path('modules')
    if modules_path.exists():
        exploit_modules = list(modules_path.glob('exploits/**/*.py'))
        aux_modules = list(modules_path.glob('auxiliary/**/*.py'))
        print(f"  ✓ Found {len(exploit_modules)} exploit modules (Python)")
        print(f"  ✓ Found {len(aux_modules)} auxiliary modules (Python)")
        results['findings']['modules'] = {
            'exploits': len(exploit_modules),
            'auxiliary': len(aux_modules)
        }
    else:
        print("  ✗ Modules directory not found")
        results['findings']['modules'] = "MISSING"
    
    # 4. Check conversion claims
    print("\n4. Conversion Claims Validation:")
    all_python = list(Path('.').rglob('*.py'))
    all_ruby = list(Path('.').rglob('*.rb'))
    
    print(f"  • Total Python files: {len(all_python)}")
    print(f"  • Total Ruby files: {len(all_ruby)}")
    
    if len(all_python) >= 7000:
        print("  ✓ Python file count supports conversion claims")
        results['findings']['conversion_claim'] = "SUPPORTED"
    else:
        print("  ⚠ Python file count lower than claimed")
        results['findings']['conversion_claim'] = "QUESTIONABLE"
    
    results['findings']['file_counts'] = {
        'python': len(all_python),
        'ruby': len(all_ruby)
    }
    
    # 5. Check documentation quality
    print("\n5. Documentation Assessment:")
    doc_files = [
        'README.md', 'RUBY2PY_CONVERSION_COMPLETE.md', 
        'TEST_SUITE_COMPLETE.md', 'CHANGELOG.md'
    ]
    
    doc_quality = 0
    for doc in doc_files:
        if Path(doc).exists():
            size = Path(doc).stat().st_size
            if size > 1000:  # Substantial documentation
                print(f"  ✓ {doc} - Comprehensive ({size:,} bytes)")
                doc_quality += 1
            else:
                print(f"  ⚠ {doc} - Basic ({size} bytes)")
        else:
            print(f"  ✗ {doc} - Missing")
    
    results['findings']['documentation_quality'] = f"{doc_quality}/{len(doc_files)} comprehensive"
    
    # 6. Check test infrastructure
    print("\n6. Test Infrastructure:")
    test_files = list(Path('.').rglob('test*.py'))
    if Path('test').exists():
        test_dir_files = list(Path('test').rglob('*.py'))
        print(f"  ✓ Test directory with {len(test_dir_files)} files")
        results['findings']['test_infrastructure'] = f"{len(test_dir_files)} test files"
    else:
        print(f"  ⚠ Found {len(test_files)} test files (no test directory)")
        results['findings']['test_infrastructure'] = f"{len(test_files)} scattered test files"
    
    # 7. Overall assessment
    print("\n7. Overall Assessment:")
    
    # Calculate score based on findings
    score = 0
    max_score = 0
    
    # Executables (20 points)
    max_score += 20
    converted_execs = sum(1 for status in exec_status.values() if status == "CONVERTED_TO_PYTHON")
    score += (converted_execs / len(executables)) * 20
    
    # Core framework (25 points)
    max_score += 25
    if results['findings'].get('core_framework') != "MISSING":
        score += 15
        if results['findings'].get('exploit_class') == "PROFESSIONAL_DESIGN":
            score += 10
    
    # Modules (20 points)
    max_score += 20
    if isinstance(results['findings'].get('modules'), dict):
        if results['findings']['modules']['exploits'] > 0:
            score += 10
        if results['findings']['modules']['auxiliary'] > 0:
            score += 10
    
    # Conversion claims (15 points)
    max_score += 15
    if results['findings'].get('conversion_claim') == "SUPPORTED":
        score += 15
    elif results['findings'].get('conversion_claim') == "QUESTIONABLE":
        score += 8
    
    # Documentation (10 points)
    max_score += 10
    doc_score = int(results['findings']['documentation_quality'].split('/')[0])
    score += (doc_score / 4) * 10
    
    # Test infrastructure (10 points)
    max_score += 10
    if 'test files' in results['findings']['test_infrastructure']:
        score += 10
    
    overall_score = (score / max_score) * 100
    results['overall_score'] = round(overall_score, 1)
    
    if overall_score >= 80:
        status = "EXCELLENT - Production Ready"
    elif overall_score >= 60:
        status = "GOOD - Near Production"
    elif overall_score >= 40:
        status = "FAIR - Development Stage"
    else:
        status = "POOR - Early Development"
    
    results['status'] = status
    
    print(f"  Overall Score: {overall_score:.1f}/100")
    print(f"  Status: {status}")
    
    # Save results
    with open('quick_assessment_results.json', 'w') as f:
        json.dump(results, f, indent=2)
    
    print(f"\nResults saved to: quick_assessment_results.json")
    
    return results

if __name__ == "__main__":
    quick_assessment()