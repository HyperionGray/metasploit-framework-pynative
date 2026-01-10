#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
Comprehensive Test Suite for MSF Python-Native Tools

This script tests all MSF executables to ensure they work properly
and are fully converted from Ruby to Python.
"""

import subprocess
import sys
from pathlib import Path
from typing import List, Tuple

MSF_ROOT = Path(__file__).resolve().parent

# All MSF executables that should be tested
MSF_EXECUTABLES = [
    'msfconsole',
    'msfvenom',
    'msfd',
    'msfdb',
    'msfrpcd',
    'msfrpc',
    'msfupdate',
    'msf',
]

# Web service scripts
WEB_SERVICES = [
    'msf-json-rpc.py',
    'msf-ws.py',
]


class TestResult:
    """Stores test result information."""
    def __init__(self, name: str, passed: bool, message: str = ""):
        self.name = name
        self.passed = passed
        self.message = message
    
    def __str__(self):
        status = "✅ PASS" if self.passed else "❌ FAIL"
        msg = f" - {self.message}" if self.message else ""
        return f"{status}: {self.name}{msg}"


def run_command(cmd: List[str], timeout: int = 5) -> Tuple[int, str, str]:
    """Run a command and return exit code, stdout, stderr."""
    try:
        result = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=timeout,
            cwd=MSF_ROOT
        )
        return result.returncode, result.stdout, result.stderr
    except subprocess.TimeoutExpired:
        return -1, "", "Command timed out"
    except Exception as e:
        return -1, "", str(e)


def test_shebang_is_python(executable: str) -> TestResult:
    """Verify executable has Python shebang."""
    path = MSF_ROOT / executable
    if not path.exists():
        return TestResult(f"{executable} shebang", False, "File not found")
    
    try:
        with open(path, 'r') as f:
            first_line = f.readline().strip()
        
        if 'python' in first_line.lower():
            return TestResult(f"{executable} shebang", True, first_line)
        else:
            return TestResult(f"{executable} shebang", False, f"Not Python: {first_line}")
    except Exception as e:
        return TestResult(f"{executable} shebang", False, str(e))


def test_executable_help(executable: str) -> TestResult:
    """Test that executable can display help."""
    returncode, stdout, stderr = run_command([f"./{executable}", "--help"])
    
    if returncode == 0:
        return TestResult(f"{executable} --help", True)
    else:
        return TestResult(f"{executable} --help", False, f"Exit code: {returncode}")


def test_executable_exists(executable: str) -> TestResult:
    """Test that executable exists and is executable."""
    path = MSF_ROOT / executable
    
    if not path.exists():
        return TestResult(f"{executable} exists", False, "Not found")
    
    if not path.is_file():
        return TestResult(f"{executable} exists", False, "Not a file")
    
    # Check if executable
    import os
    if not os.access(path, os.X_OK):
        return TestResult(f"{executable} exists", False, "Not executable")
    
    return TestResult(f"{executable} exists", True)


def test_no_ruby_references(executable: str) -> TestResult:
    """Test that executable doesn't reference Ruby."""
    path = MSF_ROOT / executable
    if not path.exists():
        return TestResult(f"{executable} no Ruby refs", False, "File not found")
    
    try:
        with open(path, 'r', encoding='utf-8', errors='ignore') as f:
            content = f.read()
        
        # Check for Ruby-specific patterns (excluding comments about migration)
        ruby_patterns = [
            'require_relative',
            'require \'',
            'require "',
            'class < ',
            'module Msf',
            'def self.',
            '@@ ',
        ]
        
        for pattern in ruby_patterns:
            if pattern in content:
                return TestResult(
                    f"{executable} no Ruby refs", 
                    False, 
                    f"Found Ruby pattern: {pattern}"
                )
        
        return TestResult(f"{executable} no Ruby refs", True)
    except Exception as e:
        return TestResult(f"{executable} no Ruby refs", False, str(e))


def test_msfvenom_list() -> TestResult:
    """Test msfvenom listing functionality."""
    returncode, stdout, stderr = run_command(['./msfvenom', '-l', 'platforms'])
    
    if returncode == 0 and 'linux' in stdout.lower():
        return TestResult("msfvenom list platforms", True)
    else:
        return TestResult("msfvenom list platforms", False, f"Exit code: {returncode}")


def test_msf_workspace() -> TestResult:
    """Test msf workspace command."""
    returncode, stdout, stderr = run_command(['./msf', 'workspace', 'list'])
    
    if returncode == 0:
        return TestResult("msf workspace list", True)
    else:
        return TestResult("msf workspace list", False, f"Exit code: {returncode}")


def test_msfdb_status() -> TestResult:
    """Test msfdb status command."""
    returncode, stdout, stderr = run_command(['./msfdb', 'status'])
    
    if returncode == 0:
        return TestResult("msfdb status", True)
    else:
        return TestResult("msfdb status", False, f"Exit code: {returncode}")


def test_web_service_help(script: str) -> TestResult:
    """Test web service script help."""
    returncode, stdout, stderr = run_command(['python3', script, '--help'])
    
    if returncode == 0:
        return TestResult(f"{script} --help", True)
    else:
        return TestResult(f"{script} --help", False, f"Exit code: {returncode}")


def test_no_ruby_files_in_root() -> TestResult:
    """Test that no Ruby rackup files exist in root."""
    ruby_files = list(MSF_ROOT.glob("*.ru"))
    
    if not ruby_files:
        return TestResult("No .ru files in root", True)
    else:
        files = ", ".join(f.name for f in ruby_files)
        return TestResult("No .ru files in root", False, f"Found: {files}")


def main():
    """Run all tests and report results."""
    print("=" * 70)
    print("  MSF Suite Python-Native Test Suite")
    print("=" * 70)
    print()
    
    results = []
    
    # Test 1: No Ruby rackup files
    print("Testing for Ruby file removal...")
    results.append(test_no_ruby_files_in_root())
    print()
    
    # Test 2: All executables exist and are executable
    print("Testing executable existence...")
    for exe in MSF_EXECUTABLES:
        results.append(test_executable_exists(exe))
    print()
    
    # Test 3: All executables have Python shebang
    print("Testing Python shebangs...")
    for exe in MSF_EXECUTABLES:
        results.append(test_shebang_is_python(exe))
    print()
    
    # Test 4: All executables don't reference Ruby
    print("Testing for Ruby code removal...")
    for exe in MSF_EXECUTABLES:
        results.append(test_no_ruby_references(exe))
    print()
    
    # Test 5: All executables show help
    print("Testing help output...")
    for exe in MSF_EXECUTABLES:
        results.append(test_executable_help(exe))
    print()
    
    # Test 6: Web services work
    print("Testing web services...")
    for ws in WEB_SERVICES:
        results.append(test_web_service_help(ws))
    print()
    
    # Test 7: Specific functionality tests
    print("Testing specific functionality...")
    results.append(test_msfvenom_list())
    results.append(test_msf_workspace())
    results.append(test_msfdb_status())
    print()
    
    # Print all results
    print("=" * 70)
    print("  Test Results")
    print("=" * 70)
    print()
    
    passed = 0
    failed = 0
    
    for result in results:
        print(result)
        if result.passed:
            passed += 1
        else:
            failed += 1
    
    print()
    print("=" * 70)
    print(f"  Total: {len(results)} tests")
    print(f"  Passed: {passed} ✅")
    print(f"  Failed: {failed} ❌")
    print("=" * 70)
    print()
    
    if failed > 0:
        print("❌ Some tests failed!")
        return 1
    else:
        print("✅ All tests passed! MSF suite is fully Python-native.")
        return 0


if __name__ == '__main__':
    sys.exit(main())
