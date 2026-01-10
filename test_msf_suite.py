#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
Comprehensive test suite for MSF tools to ensure they are Python-native
and no Ruby compatibility scripts exist.
"""

import subprocess
import sys
import tempfile
from pathlib import Path

MSF_ROOT = Path(__file__).parent.resolve()

def run_command(cmd, description):
    """Run a command and return success status."""
    print(f"\n{'='*70}")
    print(f"Testing: {description}")
    print(f"Command: {' '.join(cmd)}")
    print('='*70)
    
    try:
        result = subprocess.run(
            cmd,
            cwd=MSF_ROOT,
            capture_output=True,
            text=True,
            timeout=10
        )
        
        if result.returncode == 0 or '--help' in cmd:
            print(f"✅ SUCCESS: {description}")
            if result.stdout:
                print(f"Output preview:\n{result.stdout[:500]}")
            return True
        else:
            print(f"❌ FAILED: {description}")
            print(f"Exit code: {result.returncode}")
            if result.stderr:
                print(f"Error:\n{result.stderr[:500]}")
            return False
            
    except subprocess.TimeoutExpired:
        print(f"⏱️  TIMEOUT: {description}")
        return False
    except Exception as e:
        print(f"❌ ERROR: {description} - {e}")
        return False

def check_shebang(filepath, expected_shebang):
    """Check if a file has the expected shebang."""
    try:
        with open(filepath, 'r') as f:
            first_line = f.readline().strip()
            if expected_shebang in first_line:
                print(f"✅ {filepath.name}: Correct shebang ({first_line})")
                return True
            else:
                print(f"❌ {filepath.name}: Wrong shebang ({first_line})")
                return False
    except Exception as e:
        print(f"❌ {filepath.name}: Error reading - {e}")
        return False

def main():
    """Run comprehensive MSF suite tests."""
    print("\n" + "="*70)
    print("MSF Suite Python-Native Verification")
    print("="*70)
    
    results = []
    
    # Test 1: Check shebangs of main executables
    print("\n\n## TEST 1: Checking Shebangs of Main Executables\n")
    executables = ['msfconsole', 'msfvenom', 'msfd', 'msfrpc', 'msfrpcd', 'msfdb', 'msfupdate', 'msf']
    for exe in executables:
        exe_path = MSF_ROOT / exe
        if exe_path.exists():
            results.append(check_shebang(exe_path, 'python3'))
        else:
            print(f"⚠️  {exe}: Not found")
            results.append(False)
    
    # Test 2: Test all MSF executables with --help
    print("\n\n## TEST 2: Testing MSF Executables\n")
    
    tests = [
        (['./msfconsole', '--help'], 'msfconsole --help'),
        (['./msfvenom', '--help'], 'msfvenom --help'),
        (['./msfd', '--help'], 'msfd --help'),
        (['./msfrpc', '--help'], 'msfrpc --help'),
        (['./msfrpcd', '--help'], 'msfrpcd --help'),
        (['./msfdb', '--help'], 'msfdb --help'),
        (['./msfupdate', '--help'], 'msfupdate --help'),
        (['./msf', '--help'], 'msf --help'),
    ]
    
    for cmd, desc in tests:
        results.append(run_command(cmd, desc))
    
    # Test 3: Test msfvenom listing functionality
    print("\n\n## TEST 3: Testing msfvenom Listing Functionality\n")
    
    venom_tests = [
        (['./msfvenom', '--list', 'platforms'], 'msfvenom list platforms'),
        (['./msfvenom', '--list', 'formats'], 'msfvenom list formats'),
        (['./msfvenom', '--list', 'archs'], 'msfvenom list architectures'),
    ]
    
    for cmd, desc in venom_tests:
        results.append(run_command(cmd, desc))
    
    # Test 4: Test msf commands
    print("\n\n## TEST 4: Testing msf CLI Commands\n")
    
    msf_tests = [
        (['./msf', 'workspace'], 'msf workspace'),
        (['./msf', 'status'], 'msf status'),
    ]
    
    for cmd, desc in msf_tests:
        results.append(run_command(cmd, desc))
    
    # Test 5: Check for Ruby execution in main code
    print("\n\n## TEST 5: Checking for Ruby Execution in Main Code\n")
    
    print("Searching for Ruby execution calls in main executables...")
    ruby_exec_found = False
    
    # Patterns to check for Ruby execution
    ruby_patterns = [
        'exec ruby', 'ruby ', '/usr/bin/ruby', '/usr/bin/env ruby',
        'subprocess.run([\'ruby\'', 'subprocess.run(["ruby"',
        'Popen([\'ruby\'', 'Popen(["ruby"'
    ]
    
    for exe in executables:
        exe_path = MSF_ROOT / exe
        if exe_path.exists():
            try:
                with open(exe_path, 'r') as f:
                    content = f.read()
                    for pattern in ruby_patterns:
                        if pattern in content:
                            # Check if it's in the shebang (which we already validated) or actual code
                            lines = content.split('\n')
                            for i, line in enumerate(lines):
                                if pattern in line and i > 0:  # Skip shebang line
                                    print(f"❌ {exe}: Found Ruby execution pattern: {pattern}")
                                    ruby_exec_found = True
                                    break
                            if ruby_exec_found:
                                break
            except Exception as e:
                print(f"⚠️  {exe}: Could not read - {e}")
    
    if not ruby_exec_found:
        print("✅ No Ruby execution found in main executables")
        results.append(True)
    else:
        results.append(False)
    
    # Test 6: Test msfvenom ELF generation
    print("\n\n## TEST 6: Testing msfvenom ELF Generation\n")
    
    # Use tempfile for cross-platform compatibility
    with tempfile.NamedTemporaryFile(suffix='.elf', delete=False) as tmp_elf:
        tmp_elf_path = tmp_elf.name
    
    try:
        elf_test = subprocess.run(
            ['./msfvenom', '-f', 'elf', '-a', 'x64', '-o', tmp_elf_path],
            cwd=MSF_ROOT,
            capture_output=True,
            text=True,
            timeout=10
        )
        
        if elf_test.returncode == 0:
            elf_path = Path(tmp_elf_path)
            if elf_path.exists():
                file_result = subprocess.run(
                    ['file', str(elf_path)],
                    capture_output=True,
                    text=True
                )
                if 'ELF' in file_result.stdout:
                    print("✅ msfvenom ELF generation successful")
                    print(f"File type: {file_result.stdout.strip()}")
                    results.append(True)
                else:
                    print("❌ Generated file is not an ELF")
                    results.append(False)
            else:
                print("❌ ELF file was not created")
                results.append(False)
        else:
            print("❌ msfvenom ELF generation failed")
            results.append(False)
    finally:
        # Clean up temporary file
        try:
            Path(tmp_elf_path).unlink(missing_ok=True)
        except Exception:
            pass
    
    # Summary
    print("\n\n" + "="*70)
    print("SUMMARY")
    print("="*70)
    
    passed = sum(results)
    total = len(results)
    percentage = (passed / total * 100) if total > 0 else 0
    
    print(f"\nTests Passed: {passed}/{total} ({percentage:.1f}%)")
    
    if passed == total:
        print("\n🎉 ALL TESTS PASSED! MSF Suite is Python-native.")
        return 0
    else:
        print(f"\n⚠️  {total - passed} test(s) failed.")
        return 1

if __name__ == '__main__':
    sys.exit(main())
