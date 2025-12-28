#!/usr/bin/env python3

import subprocess
import sys
import os

os.chdir('/workspace')

print("Testing msfconsole.py...")
print("=" * 50)

# Test with --help first
print("1. Testing --help option:")
result = subprocess.run([sys.executable, 'msfconsole.py', '--help'], 
                       capture_output=True, text=True, timeout=10)
print("STDOUT:")
print(result.stdout)
if result.stderr:
    print("STDERR:")
    print(result.stderr)
print(f"Return code: {result.returncode}")

print("\n" + "=" * 50)

# Test with --version
print("2. Testing --version option:")
result = subprocess.run([sys.executable, 'msfconsole.py', '--version'], 
                       capture_output=True, text=True, timeout=10)
print("STDOUT:")
print(result.stdout)
if result.stderr:
    print("STDERR:")
    print(result.stderr)
print(f"Return code: {result.returncode}")

print("\n" + "=" * 50)

# Test basic import functionality
print("3. Testing basic import (with execute command to avoid interactive mode):")
result = subprocess.run([sys.executable, 'msfconsole.py', '-x', 'version'], 
                       capture_output=True, text=True, timeout=10)
print("STDOUT:")
print(result.stdout)
if result.stderr:
    print("STDERR:")
    print(result.stderr)
print(f"Return code: {result.returncode}")

print("\n" + "=" * 50)
print("Test completed!")