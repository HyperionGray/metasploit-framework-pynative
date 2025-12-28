#!/usr/bin/env python3
"""
Build validation script to test if the cleaned configuration files work properly.
This script mimics the CI/CD build process to identify any remaining issues.
"""

import subprocess
import sys
import os
from pathlib import Path

def run_command(cmd, description, continue_on_error=True):
    """Run a command and report the result"""
    print(f"\n🔍 {description}")
    print(f"Command: {' '.join(cmd)}")
    
    try:
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=300)
        if result.returncode == 0:
            print(f"✅ {description} - SUCCESS")
            if result.stdout.strip():
                print(f"Output: {result.stdout.strip()[:200]}...")
            return True
        else:
            print(f"❌ {description} - FAILED")
            if result.stderr.strip():
                print(f"Error: {result.stderr.strip()[:500]}...")
            if not continue_on_error:
                sys.exit(1)
            return False
    except subprocess.TimeoutExpired:
        print(f"⏰ {description} - TIMEOUT")
        return False
    except Exception as e:
        print(f"💥 {description} - EXCEPTION: {e}")
        return False

def check_file_exists(filepath, description):
    """Check if a file exists"""
    if Path(filepath).exists():
        print(f"✅ {description} - EXISTS")
        return True
    else:
        print(f"❌ {description} - MISSING")
        return False

def validate_pyproject_toml():
    """Validate pyproject.toml syntax"""
    print("\n📋 Validating pyproject.toml...")
    try:
        import tomllib
        with open('pyproject.toml', 'rb') as f:
            data = tomllib.load(f)
        print("✅ pyproject.toml syntax is valid")
        
        # Check for pytest configuration
        if 'tool' in data and 'pytest' in data['tool']:
            print("✅ pytest configuration found")
        else:
            print("⚠️ pytest configuration not found")
            
        return True
    except Exception as e:
        print(f"❌ pyproject.toml validation failed: {e}")
        return False

def main():
    """Main validation function"""
    print("🚀 Starting build validation...")
    
    # Check if we're in the right directory
    if not Path('pyproject.toml').exists():
        print("❌ pyproject.toml not found. Are you in the project root?")
        sys.exit(1)
    
    results = []
    
    # 1. Check essential files
    print("\n📁 Checking essential files...")
    essential_files = [
        ('README.md', 'README file'),
        ('requirements.txt', 'Requirements file'),
        ('pyproject.toml', 'Project configuration'),
        ('LICENSE.md', 'License file'),
        ('CHANGELOG.md', 'Changelog file'),
        ('SECURITY.md', 'Security policy'),
        ('CONTRIBUTING.md', 'Contributing guidelines'),
        ('CODE_OF_CONDUCT.md', 'Code of conduct')
    ]
    
    for filepath, description in essential_files:
        results.append(check_file_exists(filepath, description))
    
    # 2. Validate pyproject.toml
    results.append(validate_pyproject_toml())
    
    # 3. Test Python syntax
    results.append(run_command([
        sys.executable, '-m', 'py_compile', 'tasks.py'
    ], "Python syntax check for tasks.py"))
    
    # 4. Test requirements.txt installation (dry run)
    results.append(run_command([
        sys.executable, '-m', 'pip', 'install', '--dry-run', '-r', 'requirements.txt'
    ], "Requirements.txt dry-run installation"))
    
    # 5. Test pytest configuration
    results.append(run_command([
        sys.executable, '-m', 'pytest', '--collect-only', '--quiet'
    ], "Pytest configuration test"))
    
    # 6. Test code quality tools configuration
    if Path('requirements.txt').exists():
        # Test flake8 configuration
        results.append(run_command([
            sys.executable, '-m', 'flake8', '--version'
        ], "Flake8 availability check"))
        
        # Test black configuration  
        results.append(run_command([
            sys.executable, '-m', 'black', '--version'
        ], "Black availability check"))
    
    # Summary
    print("\n" + "="*60)
    print("📊 VALIDATION SUMMARY")
    print("="*60)
    
    passed = sum(results)
    total = len(results)
    
    print(f"✅ Passed: {passed}/{total}")
    print(f"❌ Failed: {total - passed}/{total}")
    
    if passed == total:
        print("\n🎉 All validations passed! Build should succeed.")
        return 0
    else:
        print(f"\n⚠️ {total - passed} validations failed. Build may have issues.")
        return 1

if __name__ == "__main__":
    sys.exit(main())