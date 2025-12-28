#!/usr/bin/env python3

"""
Simple test runner to validate our MSF PyNative implementation
"""

import subprocess
import sys
import os

def run_test(description, command):
    """Run a single test and report results"""
    print(f"\n{'='*60}")
    print(f"TEST: {description}")
    print(f"COMMAND: {command}")
    print(f"{'='*60}")
    
    try:
        result = subprocess.run(command, shell=True, capture_output=True, text=True, timeout=30)
        
        print(f"EXIT CODE: {result.returncode}")
        
        if result.stdout:
            print(f"\nSTDOUT:")
            print(result.stdout)
            
        if result.stderr:
            print(f"\nSTDERR:")
            print(result.stderr)
            
        success = result.returncode == 0
        print(f"\nRESULT: {'✅ PASS' if success else '❌ FAIL'}")
        
        return success
        
    except subprocess.TimeoutExpired:
        print("❌ FAIL - Command timed out")
        return False
    except Exception as e:
        print(f"❌ FAIL - Exception: {e}")
        return False

def main():
    """Run all tests"""
    print("Metasploit Framework PyNative - Basic Functionality Test")
    print("=" * 60)
    
    tests = [
        ("Python Version Check", "python3 --version"),
        ("msfconsole.py Help", "python3 msfconsole.py -h"),
        ("msfconsole.py Version", "python3 msfconsole.py -v"),
        ("msfconsole.py Execute Command", 'python3 msfconsole.py -q -x "version; exit"'),
        ("msfvenom Help", "python3 msfvenom -h"),
        ("msfvenom List Payloads", "python3 msfvenom -l payloads"),
        ("msfvenom List Formats", "python3 msfvenom -l formats"),
        ("msfvenom Basic Payload Generation", "python3 msfvenom -p generic/shell_reverse_tcp LHOST=127.0.0.1")
    ]
    
    results = []
    
    for description, command in tests:
        success = run_test(description, command)
        results.append((description, success))
    
    # Summary
    print(f"\n{'='*60}")
    print("TEST SUMMARY")
    print(f"{'='*60}")
    
    passed = sum(1 for _, success in results if success)
    total = len(results)
    
    for description, success in results:
        status = "✅ PASS" if success else "❌ FAIL"
        print(f"{status} {description}")
    
    print(f"\nTotal: {total}, Passed: {passed}, Failed: {total - passed}")
    print(f"Success Rate: {(passed/total)*100:.1f}%")
    
    if passed == total:
        print("\n🎉 All tests passed! The MSF PyNative implementation is working correctly.")
    else:
        print(f"\n⚠️  {total - passed} test(s) failed. See details above.")
    
    return 0 if passed == total else 1

if __name__ == "__main__":
    sys.exit(main())