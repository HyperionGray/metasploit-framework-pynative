#!/usr/bin/env python3
"""
Build Status Verification Script

This script verifies that the build issues identified in the CI/CD review have been resolved.
It checks:
1. Test runner functionality
2. Requirements file integrity  
3. Configuration file validity
4. Basic test execution
"""

import subprocess
import sys
import os
from pathlib import Path


def check_test_runner():
    """Check if the test runner script works."""
    print("🔍 Checking test runner functionality...")
    
    try:
        # Test help command
        result = subprocess.run([
            sys.executable, "run_tests.py", "--help"
        ], capture_output=True, text=True, timeout=30)
        
        if result.returncode == 0:
            print("✅ Test runner help command works")
            return True
        else:
            print(f"❌ Test runner help failed: {result.stderr}")
            return False
    except Exception as e:
        print(f"❌ Test runner check failed: {e}")
        return False


def check_requirements():
    """Check if requirements.txt is valid."""
    print("🔍 Checking requirements.txt validity...")
    
    try:
        # Try to parse requirements file
        with open("requirements.txt", "r") as f:
            lines = f.readlines()
        
        # Check for duplicates
        packages = []
        for line in lines:
            line = line.strip()
            if line and not line.startswith('#'):
                if '>=' in line:
                    pkg = line.split('>=')[0].strip()
                    packages.append(pkg)
        
        duplicates = [pkg for pkg in set(packages) if packages.count(pkg) > 1]
        if duplicates:
            print(f"❌ Duplicate packages found: {duplicates}")
            return False
        
        print(f"✅ Requirements file is clean ({len(packages)} unique packages)")
        return True
        
    except Exception as e:
        print(f"❌ Requirements check failed: {e}")
        return False


def check_pytest_config():
    """Check if pytest configuration is valid."""
    print("🔍 Checking pytest configuration...")
    
    try:
        # Test pytest configuration
        result = subprocess.run([
            sys.executable, "-m", "pytest", "--collect-only", "-q"
        ], capture_output=True, text=True, timeout=30)
        
        if result.returncode == 0:
            print("✅ Pytest configuration is valid")
            return True
        else:
            print(f"❌ Pytest configuration error: {result.stderr}")
            return False
            
    except Exception as e:
        print(f"❌ Pytest config check failed: {e}")
        return False


def run_basic_tests():
    """Run basic build verification tests."""
    print("🔍 Running basic build verification tests...")
    
    try:
        # Run our build verification tests
        result = subprocess.run([
            sys.executable, "run_tests.py", "--unit", "--verbose"
        ], capture_output=True, text=True, timeout=60)
        
        if result.returncode == 0:
            print("✅ Basic tests passed")
            return True
        else:
            print(f"❌ Basic tests failed: {result.stderr}")
            print(f"stdout: {result.stdout}")
            return False
            
    except Exception as e:
        print(f"❌ Basic test execution failed: {e}")
        return False


def main():
    """Main verification function."""
    print("🚀 Starting build status verification...")
    print("=" * 60)
    
    checks = [
        ("Test Runner", check_test_runner),
        ("Requirements File", check_requirements), 
        ("Pytest Configuration", check_pytest_config),
        ("Basic Tests", run_basic_tests)
    ]
    
    results = []
    for name, check_func in checks:
        print(f"\n📋 {name}:")
        success = check_func()
        results.append((name, success))
    
    print("\n" + "=" * 60)
    print("📊 VERIFICATION SUMMARY:")
    
    all_passed = True
    for name, success in results:
        status = "✅ PASS" if success else "❌ FAIL"
        print(f"  {name}: {status}")
        if not success:
            all_passed = False
    
    print("\n" + "=" * 60)
    if all_passed:
        print("🎉 BUILD STATUS: SUCCESS")
        print("All build issues have been resolved!")
        return 0
    else:
        print("💥 BUILD STATUS: FAILURE") 
        print("Some build issues remain unresolved.")
        return 1


if __name__ == "__main__":
    sys.exit(main())