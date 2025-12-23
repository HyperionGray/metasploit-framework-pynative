#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
Verification script for the comprehensive test suite.
This script validates that all components are properly installed and configured.
"""

import os
import sys
import ast
from pathlib import Path
from typing import List, Tuple


def print_header(message: str):
    """Print a formatted header."""
    print(f"\n{'=' * 70}")
    print(f"  {message}")
    print(f"{'=' * 70}\n")


def print_success(message: str):
    """Print a success message."""
    print(f"✅ {message}")


def print_error(message: str):
    """Print an error message."""
    print(f"❌ {message}")


def print_info(message: str):
    """Print an info message."""
    print(f"ℹ️  {message}")


def check_file_exists(file_path: str) -> Tuple[bool, int]:
    """Check if a file exists and return its size."""
    path = Path(file_path)
    if path.exists():
        return True, path.stat().st_size
    return False, 0


def check_file_syntax(file_path: str) -> Tuple[bool, str]:
    """Check if a Python file has valid syntax."""
    try:
        with open(file_path, 'r') as f:
            code = f.read()
            ast.parse(code)
        return True, "Valid"
    except SyntaxError as e:
        return False, str(e)
    except Exception as e:
        return False, str(e)


def check_file_executable(file_path: str) -> bool:
    """Check if a file is executable."""
    return os.access(file_path, os.X_OK)


def main():
    """Main verification function."""
    print_header("Comprehensive Test Suite Verification")
    
    all_checks_passed = True
    
    # Check test files
    print_header("Test Files")
    test_files = [
        'test/test_comprehensive_suite.py',
        'test/test_property_based.py',
        'test/test_fuzz.py',
        'test/test_integration_comprehensive.py',
    ]
    
    for test_file in test_files:
        exists, size = check_file_exists(test_file)
        if exists:
            valid, msg = check_file_syntax(test_file)
            if valid:
                print_success(f"{test_file:50s} ({size:,} bytes, syntax OK)")
            else:
                print_error(f"{test_file:50s} (syntax error: {msg})")
                all_checks_passed = False
        else:
            print_error(f"{test_file:50s} (missing)")
            all_checks_passed = False
    
    # Check automation scripts
    print_header("Automation Scripts")
    scripts = [
        ('run_comprehensive_tests.py', True),  # Should be executable
        ('scripts/pre-commit', True),
        ('scripts/test-quickstart.sh', True),
    ]
    
    for script, should_be_executable in scripts:
        exists, size = check_file_exists(script)
        if exists:
            is_executable = check_file_executable(script)
            exec_status = "executable" if is_executable else "not executable"
            
            if script.endswith('.py'):
                valid, msg = check_file_syntax(script)
                if valid and (not should_be_executable or is_executable):
                    print_success(f"{script:50s} ({size:,} bytes, {exec_status}, syntax OK)")
                else:
                    if not valid:
                        print_error(f"{script:50s} (syntax error: {msg})")
                        all_checks_passed = False
                    elif should_be_executable and not is_executable:
                        print_error(f"{script:50s} (not executable)")
                        all_checks_passed = False
            else:
                if should_be_executable and is_executable:
                    print_success(f"{script:50s} ({size:,} bytes, {exec_status})")
                elif should_be_executable and not is_executable:
                    print_error(f"{script:50s} (not executable)")
                    all_checks_passed = False
                else:
                    print_success(f"{script:50s} ({size:,} bytes)")
        else:
            print_error(f"{script:50s} (missing)")
            all_checks_passed = False
    
    # Check documentation
    print_header("Documentation")
    docs = [
        'TESTING_COMPREHENSIVE_GUIDE.md',
        'TEST_SUITE_COMPLETE.md',
        'test/README.md',
    ]
    
    for doc in docs:
        exists, size = check_file_exists(doc)
        if exists:
            print_success(f"{doc:50s} ({size:,} bytes)")
        else:
            print_error(f"{doc:50s} (missing)")
            all_checks_passed = False
    
    # Check CI/CD
    print_header("CI/CD Configuration")
    ci_files = [
        '.github/workflows/comprehensive-nightly-tests.yml',
        'Makefile.testing',
    ]
    
    for ci_file in ci_files:
        exists, size = check_file_exists(ci_file)
        if exists:
            print_success(f"{ci_file:50s} ({size:,} bytes)")
        else:
            print_error(f"{ci_file:50s} (missing)")
            all_checks_passed = False
    
    # Test imports
    print_header("Python Import Tests")
    
    # Test run_comprehensive_tests import
    try:
        sys.path.insert(0, str(Path(__file__).parent))
        import run_comprehensive_tests
        print_success("run_comprehensive_tests.py can be imported")
    except Exception as e:
        print_error(f"run_comprehensive_tests.py import failed: {e}")
        all_checks_passed = False
    
    # Count test cases
    print_header("Test Statistics")
    
    total_lines = 0
    for test_file in test_files:
        if Path(test_file).exists():
            with open(test_file, 'r') as f:
                lines = len(f.readlines())
                total_lines += lines
    
    print_info(f"Total test code: {total_lines:,} lines across {len(test_files)} files")
    
    # Summary
    print_header("Verification Summary")
    
    if all_checks_passed:
        print_success("All verification checks passed! ✨")
        print_info("The comprehensive test suite is ready to use!")
        print_info("\nQuick start:")
        print_info("  ./run_comprehensive_tests.py --help")
        print_info("  ./scripts/test-quickstart.sh")
        print_info("  make -f Makefile.testing help")
        return 0
    else:
        print_error("Some verification checks failed!")
        print_info("Please review the errors above and fix the issues.")
        return 1


if __name__ == '__main__':
    sys.exit(main())
