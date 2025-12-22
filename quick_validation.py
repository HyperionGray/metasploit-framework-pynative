#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Quick Framework Validation Script

This script performs a rapid health check of the Metasploit Framework
Ruby-to-Python conversion to identify immediate issues and provide
actionable recommendations.

Usage: python3 quick_validation.py
"""

import sys
import os
import subprocess
from pathlib import Path
import importlib.util


def print_header(title):
    """Print a formatted header"""
    print(f"\n{'='*60}")
    print(f"🔍 {title}")
    print('='*60)


def print_status(item, status, details=""):
    """Print status with appropriate icon"""
    icons = {"✅": "✅", "❌": "❌", "⚠️": "⚠️", "ℹ️": "ℹ️"}
    icon = icons.get(status, status)
    print(f"{icon} {item:<40} {details}")


def check_python_version():
    """Check Python version compatibility"""
    print_header("Python Environment")
    
    version = sys.version_info
    version_str = f"{version.major}.{version.minor}.{version.micro}"
    
    if version >= (3, 8):
        print_status("Python Version", "✅", f"v{version_str} (Compatible)")
        return True
    else:
        print_status("Python Version", "❌", f"v{version_str} (Requires 3.8+)")
        return False


def check_framework_structure():
    """Check framework directory structure"""
    print_header("Framework Structure")
    
    required_dirs = {
        'lib': 'Core framework libraries',
        'modules': 'Exploit and auxiliary modules',
        'tools': 'Framework tools and utilities',
        'test': 'Test suite',
        'spec': 'Specification tests',
        'data': 'Framework data files'
    }
    
    all_good = True
    for dir_name, description in required_dirs.items():
        path = Path(dir_name)
        if path.exists() and path.is_dir():
            file_count = len(list(path.rglob('*')))
            print_status(f"{dir_name}/ directory", "✅", f"{file_count} files")
        else:
            print_status(f"{dir_name}/ directory", "❌", "Missing")
            all_good = False
    
    return all_good


def check_python_files():
    """Check for Python files in key directories"""
    print_header("Python Module Conversion")
    
    directories = ['lib', 'modules', 'tools']
    total_python_files = 0
    
    for directory in directories:
        path = Path(directory)
        if path.exists():
            python_files = list(path.rglob('*.py'))
            ruby_files = list(path.rglob('*.rb'))
            
            total_python_files += len(python_files)
            
            if len(python_files) > 0:
                print_status(f"{directory}/ Python files", "✅", f"{len(python_files)} files")
            else:
                print_status(f"{directory}/ Python files", "❌", "No Python files found")
            
            if len(ruby_files) > 0:
                print_status(f"{directory}/ Ruby files", "ℹ️", f"{len(ruby_files)} remaining")
    
    if total_python_files > 100:
        print_status("Conversion Progress", "✅", f"{total_python_files} Python modules")
        return True
    else:
        print_status("Conversion Progress", "⚠️", f"Only {total_python_files} Python modules")
        return False


def check_dependencies():
    """Check critical dependencies"""
    print_header("Dependencies")
    
    critical_deps = [
        ('pytest', 'Testing framework'),
        ('requests', 'HTTP client library'),
        ('cryptography', 'Cryptographic functions'),
        ('pyyaml', 'YAML parsing'),
        ('scapy', 'Network packet manipulation'),
        ('pwntools', 'Exploit development'),
    ]
    
    missing_deps = []
    
    for dep_name, description in critical_deps:
        try:
            spec = importlib.util.find_spec(dep_name)
            if spec is not None:
                print_status(dep_name, "✅", description)
            else:
                print_status(dep_name, "❌", f"Not found - {description}")
                missing_deps.append(dep_name)
        except ImportError:
            print_status(dep_name, "❌", f"Import error - {description}")
            missing_deps.append(dep_name)
    
    if missing_deps:
        print(f"\n💡 Install missing dependencies:")
        print(f"   pip3 install {' '.join(missing_deps)}")
        print(f"   OR: python3 tasks.py install")
    
    return len(missing_deps) == 0


def check_configuration_files():
    """Check configuration files"""
    print_header("Configuration Files")
    
    config_files = {
        'requirements.txt': 'Python dependencies',
        'pyproject.toml': 'Python project configuration',
        'tasks.py': 'Task runner (Python equivalent of Rakefile)',
        '.flake8': 'Python linting configuration',
    }
    
    all_good = True
    for file_name, description in config_files.items():
        path = Path(file_name)
        if path.exists() and path.is_file():
            size = path.stat().st_size
            print_status(file_name, "✅", f"{description} ({size} bytes)")
        else:
            print_status(file_name, "❌", f"Missing - {description}")
            all_good = False
    
    return all_good


def check_test_infrastructure():
    """Check test infrastructure"""
    print_header("Test Infrastructure")
    
    test_files = list(Path('test').rglob('*.py')) if Path('test').exists() else []
    spec_files = list(Path('spec').rglob('*.py')) if Path('spec').exists() else []
    
    total_tests = len(test_files) + len(spec_files)
    
    if total_tests > 0:
        print_status("Test Files", "✅", f"{total_tests} Python test files")
    else:
        print_status("Test Files", "❌", "No Python test files found")
    
    # Check if pytest can be run
    try:
        result = subprocess.run(['python3', '-m', 'pytest', '--version'], 
                              capture_output=True, text=True, timeout=10)
        if result.returncode == 0:
            version = result.stdout.strip()
            print_status("Pytest Executable", "✅", version)
        else:
            print_status("Pytest Executable", "❌", "Cannot run pytest")
    except (subprocess.TimeoutExpired, FileNotFoundError):
        print_status("Pytest Executable", "❌", "Pytest not available")
    
    return total_tests > 0


def run_quick_test():
    """Run a quick test to validate basic functionality"""
    print_header("Quick Functionality Test")
    
    try:
        # Test basic Python functionality
        import hashlib
        import base64
        import json
        
        # Test crypto functions
        test_data = b"test"
        hash_result = hashlib.sha256(test_data).hexdigest()
        b64_result = base64.b64encode(test_data).decode()
        
        print_status("Crypto Functions", "✅", "SHA256 and Base64 working")
        
        # Test JSON handling
        test_obj = {"test": "data"}
        json_str = json.dumps(test_obj)
        parsed_obj = json.loads(json_str)
        
        print_status("JSON Processing", "✅", "Serialization working")
        
        # Test file operations
        test_file = Path("test_validation.tmp")
        test_file.write_text("test content")
        content = test_file.read_text()
        test_file.unlink()
        
        print_status("File Operations", "✅", "Read/write working")
        
        return True
        
    except Exception as e:
        print_status("Basic Functions", "❌", f"Error: {str(e)[:50]}")
        return False


def provide_recommendations():
    """Provide actionable recommendations"""
    print_header("Recommendations")
    
    print("🚀 Next Steps:")
    print()
    
    # Check current state and provide specific recommendations
    if not Path('requirements.txt').exists() or Path('requirements.txt').stat().st_size < 100:
        print("1. Fix requirements.txt file:")
        print("   cp requirements.txt.backup requirements.txt")
        print()
    
    if not any(Path(d).exists() for d in ['lib', 'modules']):
        print("1. Framework structure missing - check conversion:")
        print("   Ensure Ruby-to-Python conversion completed successfully")
        print()
    
    print("2. Install dependencies:")
    print("   python3 tasks.py install")
    print()
    
    print("3. Validate setup:")
    print("   python3 tasks.py validate")
    print()
    
    print("4. Run quick tests:")
    print("   python3 test_runner_comprehensive.py --quick")
    print()
    
    print("5. Run comprehensive tests:")
    print("   python3 test_runner_comprehensive.py --coverage")
    print()
    
    print("📚 For detailed guidance, see:")
    print("   - TESTING_GUIDE.md")
    print("   - README.md")
    print("   - RUBY_TO_PYTHON_COMPLETE.md")


def main():
    """Main validation function"""
    print("🔍 Metasploit Framework Ruby-to-Python Conversion Validator")
    print("=" * 60)
    
    checks = [
        ("Python Version", check_python_version),
        ("Framework Structure", check_framework_structure),
        ("Python Conversion", check_python_files),
        ("Dependencies", check_dependencies),
        ("Configuration", check_configuration_files),
        ("Test Infrastructure", check_test_infrastructure),
        ("Basic Functionality", run_quick_test),
    ]
    
    results = {}
    for check_name, check_func in checks:
        try:
            results[check_name] = check_func()
        except Exception as e:
            print_status(check_name, "❌", f"Check failed: {e}")
            results[check_name] = False
    
    # Summary
    print_header("Validation Summary")
    
    passed = sum(results.values())
    total = len(results)
    
    print(f"✅ Passed: {passed}/{total}")
    print(f"❌ Failed: {total - passed}/{total}")
    
    if passed == total:
        print("\n🎉 All checks passed! Framework appears ready for testing.")
        print("   Run: python3 test_runner_comprehensive.py --quick")
    elif passed >= total * 0.7:
        print("\n⚠️  Most checks passed. Address remaining issues:")
        for check_name, result in results.items():
            if not result:
                print(f"   - Fix: {check_name}")
    else:
        print("\n❌ Multiple issues detected. Framework needs attention.")
    
    provide_recommendations()
    
    return passed == total


if __name__ == '__main__':
    success = main()
    sys.exit(0 if success else 1)