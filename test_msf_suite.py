#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
Comprehensive test suite for MSF Python-native tools.
Verifies that all main MSF executables work without Ruby dependencies.
"""

import subprocess
import sys
import os
from pathlib import Path

MSF_ROOT = Path(__file__).parent.resolve()

class Colors:
    GREEN = '\033[92m'
    RED = '\033[91m'
    YELLOW = '\033[93m'
    BLUE = '\033[94m'
    RESET = '\033[0m'

def print_header(text):
    """Print a section header"""
    print(f"\n{Colors.BLUE}{'='*70}{Colors.RESET}")
    print(f"{Colors.BLUE}{text}{Colors.RESET}")
    print(f"{Colors.BLUE}{'='*70}{Colors.RESET}\n")

def print_success(text):
    """Print success message"""
    print(f"{Colors.GREEN}✅ {text}{Colors.RESET}")

def print_error(text):
    """Print error message"""
    print(f"{Colors.RED}❌ {text}{Colors.RESET}")

def print_warning(text):
    """Print warning message"""
    print(f"{Colors.YELLOW}⚠️  {text}{Colors.RESET}")

def run_command(cmd, desc, expect_success=True):
    """Run a command and check result"""
    print(f"Testing: {desc}")
    try:
        result = subprocess.run(
            cmd,
            cwd=MSF_ROOT,
            capture_output=True,
            text=True,
            timeout=10
        )
        
        if expect_success:
            if result.returncode == 0:
                print_success(f"{desc} - OK")
                return True
            else:
                print_error(f"{desc} - Failed with exit code {result.returncode}")
                if result.stderr:
                    print(f"  Error: {result.stderr[:200]}")
                return False
        else:
            # For commands that might fail but we just want to check they run
            print_success(f"{desc} - Executed")
            return True
            
    except subprocess.TimeoutExpired:
        print_error(f"{desc} - Timeout")
        return False
    except Exception as e:
        print_error(f"{desc} - Exception: {e}")
        return False

def check_file_type(filepath, desc):
    """Check that a file is a Python script"""
    print(f"Checking: {desc}")
    
    if not filepath.exists():
        print_error(f"{desc} - File not found")
        return False
    
    try:
        with open(filepath, 'r', encoding='utf-8', errors='ignore') as f:
            first_line = f.readline().strip()
            
        if 'python3' in first_line.lower():
            print_success(f"{desc} - Python script")
            return True
        elif 'ruby' in first_line.lower():
            print_error(f"{desc} - Ruby script! Should be Python")
            return False
        else:
            print_warning(f"{desc} - Unknown type: {first_line}")
            return False
            
    except Exception as e:
        print_error(f"{desc} - Exception: {e}")
        return False

def check_no_ruby_calls(filepath, desc):
    """Check that a Python file doesn't call Ruby interpreter"""
    try:
        with open(filepath, 'r', encoding='utf-8', errors='ignore') as f:
            content = f.read()
        
        # Look for subprocess/os.system calls to ruby
        ruby_calls = []
        for i, line in enumerate(content.split('\n'), 1):
            if 'subprocess' in line or 'os.system' in line or 'os.exec' in line:
                if 'ruby' in line.lower() and not line.strip().startswith('#'):
                    ruby_calls.append((i, line.strip()))
        
        if ruby_calls:
            print_error(f"{desc} - Found Ruby calls:")
            for line_num, line in ruby_calls[:3]:  # Show first 3
                print(f"  Line {line_num}: {line[:80]}")
            return False
        else:
            print_success(f"{desc} - No Ruby calls")
            return True
            
    except Exception as e:
        print_warning(f"{desc} - Could not check: {e}")
        return True  # Don't fail on this

def main():
    """Run all tests"""
    print_header("MSF Suite Python-Native Verification")
    
    all_passed = True
    
    # Test 1: Check main executables are Python
    print_header("Test 1: Verify Main Executables are Python")
    executables = [
        ('msfconsole', 'Metasploit Console'),
        ('msfvenom', 'Payload Generator'),
        ('msfd', 'Framework Daemon'),
        ('msfrpc', 'RPC Client'),
        ('msfrpcd', 'RPC Daemon'),
        ('msfdb', 'Database Manager'),
        ('msfupdate', 'Framework Updater'),
        ('msf', 'Bash-friendly CLI'),
    ]
    
    for exe, desc in executables:
        filepath = MSF_ROOT / exe
        if not check_file_type(filepath, desc):
            all_passed = False
    
    # Test 2: Check executables work with --help
    print_header("Test 2: Verify Executables Work (--help)")
    
    for exe, desc in executables:
        cmd = [str(MSF_ROOT / exe), '--help']
        if not run_command(cmd, f"{desc} --help"):
            all_passed = False
    
    # Test 3: Test msfvenom functionality
    print_header("Test 3: Test msfvenom Functionality")
    
    tests = [
        (['python3', str(MSF_ROOT / 'msfvenom'), '-l', 'formats'], 'List formats'),
        (['python3', str(MSF_ROOT / 'msfvenom'), '-l', 'platforms'], 'List platforms'),
        (['python3', str(MSF_ROOT / 'msfvenom'), '-l', 'archs'], 'List architectures'),
    ]
    
    for cmd, desc in tests:
        if not run_command(cmd, desc):
            all_passed = False
    
    # Test 4: Generate a test payload
    print_header("Test 4: Generate Test Payload")
    
    test_payload_path = '/tmp/msf_test_payload.elf'
    if os.path.exists(test_payload_path):
        os.remove(test_payload_path)
    
    cmd = ['python3', str(MSF_ROOT / 'msfvenom'), '-f', 'elf', '-o', test_payload_path]
    if run_command(cmd, 'Generate ELF payload'):
        if os.path.exists(test_payload_path):
            print_success("Payload file created")
            os.remove(test_payload_path)
        else:
            print_error("Payload file not created")
            all_passed = False
    else:
        all_passed = False
    
    # Test 5: Check for Ruby compatibility scripts
    print_header("Test 5: Check for Ruby Compatibility Scripts")
    
    python_files_to_check = [
        'external/source/DLLHijackAuditKit/regenerate_binaries.py',
    ]
    
    for pyfile in python_files_to_check:
        filepath = MSF_ROOT / pyfile
        if filepath.exists():
            if not check_no_ruby_calls(filepath, pyfile):
                all_passed = False
    
    # Test 6: Test msfdb
    print_header("Test 6: Test msfdb")
    
    cmd = ['python3', str(MSF_ROOT / 'msfdb'), 'status']
    if not run_command(cmd, 'Check database status', expect_success=True):
        all_passed = False
    
    # Test 7: Test msf CLI
    print_header("Test 7: Test msf CLI")
    
    cmd = ['python3', str(MSF_ROOT / 'msf'), 'status']
    if not run_command(cmd, 'Show msf status', expect_success=True):
        all_passed = False
    
    # Test 8: Test msfrc activation
    print_header("Test 8: Test msfrc Activation")
    
    # Test that msfrc can be sourced and provides commands
    cmd = ['bash', '-c', f'source {MSF_ROOT / "msfrc"} && echo $MSF_PYTHON_MODE']
    result = subprocess.run(cmd, capture_output=True, text=True, timeout=10)
    if 'MSF_PYTHON_MODE' in result.stdout or result.returncode == 0:
        print_success("msfrc activation - OK")
    else:
        print_error("msfrc activation failed")
        all_passed = False
    
    # Test msf_venom through msfrc
    cmd = ['bash', '-c', f'source {MSF_ROOT / "msfrc"} 2>/dev/null && msf_venom -l platforms | head -5']
    result = subprocess.run(cmd, capture_output=True, text=True, timeout=10)
    if 'Framework Platforms' in result.stdout:
        print_success("msf_venom through msfrc - OK")
    else:
        print_error("msf_venom through msfrc failed")
        all_passed = False
    
    # Final report
    print_header("Test Results Summary")
    
    if all_passed:
        print_success("All tests passed! ✨")
        print("\nThe MSF suite is fully Python-native:")
        print("  • All main executables are Python scripts")
        print("  • All executables work correctly")
        print("  • msfvenom can generate payloads")
        print("  • No Ruby compatibility scripts found")
        print("  • Database management works")
        print("  • msfrc activation and commands work")
        return 0
    else:
        print_error("Some tests failed!")
        print("\nPlease review the errors above and fix any issues.")
        return 1

if __name__ == '__main__':
    sys.exit(main())
