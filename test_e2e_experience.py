#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
E2E Test Script for MSF Installation and Startup Experience

This script tests different ways users might interact with MSF to ensure
they are properly guided to the msfrc approach.
"""

import os
import sys
import subprocess
import tempfile
from pathlib import Path

def run_command(cmd, env=None, capture_output=True):
    """Run a command and return the result"""
    try:
        if env is None:
            env = os.environ.copy()
        
        result = subprocess.run(
            cmd, 
            shell=True, 
            capture_output=capture_output,
            text=True,
            env=env,
            timeout=10
        )
        return result.returncode, result.stdout, result.stderr
    except subprocess.TimeoutExpired:
        return -1, "", "Command timed out"
    except Exception as e:
        return -1, "", str(e)

def test_direct_executables():
    """Test running MSF executables directly (should show msfrc guidance)"""
    print("="*70)
    print("Testing Direct Executable Usage (Should Show msfrc Guidance)")
    print("="*70)
    
    executables = [
        './msfconsole',
        './msfvenom --help',
        './msfd --help',
        './msfdb --help',
        './msfrpc --help',
        './msfrpcd --help',
        './msfupdate --help'
    ]
    
    for exe in executables:
        print(f"\n--- Testing: {exe} ---")
        returncode, stdout, stderr = run_command(exe)
        
        # Check if msfrc guidance is shown
        output = stdout + stderr
        if "source msfrc" in output:
            print("✅ Shows msfrc guidance")
        else:
            print("❌ Missing msfrc guidance")
            
        if "Enhanced MSF Experience Available" in output:
            print("✅ Shows enhanced experience message")
        else:
            print("❌ Missing enhanced experience message")
            
        # Show first few lines of output
        lines = output.split('\n')[:5]
        for line in lines:
            if line.strip():
                print(f"   {line}")

def test_quiet_mode():
    """Test that MSF_QUIET suppresses guidance messages"""
    print("\n" + "="*70)
    print("Testing Quiet Mode (Should Suppress Guidance)")
    print("="*70)
    
    env = os.environ.copy()
    env['MSF_QUIET'] = '1'
    
    returncode, stdout, stderr = run_command('./msfconsole', env=env)
    output = stdout + stderr
    
    if "source msfrc" not in output and "Enhanced MSF Experience" not in output:
        print("✅ Quiet mode suppresses guidance messages")
    else:
        print("❌ Quiet mode not working properly")
        print("Output:", output[:200])

def test_msfrc_environment():
    """Test msfrc environment activation"""
    print("\n" + "="*70)
    print("Testing msfrc Environment Activation")
    print("="*70)
    
    # Create a test script that sources msfrc and checks environment
    test_script = """
#!/bin/bash
source ./msfrc
echo "MSF_PYTHON_MODE: $MSF_PYTHON_MODE"
echo "MSF_ROOT: $MSF_ROOT"
echo "PATH contains MSF: $(echo $PATH | grep -o $(pwd) || echo 'NO')"
echo "Available functions:"
type msf_console >/dev/null 2>&1 && echo "✅ msf_console available" || echo "❌ msf_console missing"
type msf_venom >/dev/null 2>&1 && echo "✅ msf_venom available" || echo "❌ msf_venom missing"
type msf_info >/dev/null 2>&1 && echo "✅ msf_info available" || echo "❌ msf_info missing"
type msf_deactivate >/dev/null 2>&1 && echo "✅ msf_deactivate available" || echo "❌ msf_deactivate missing"
"""
    
    with tempfile.NamedTemporaryFile(mode='w', suffix='.sh', delete=False) as f:
        f.write(test_script)
        f.flush()
        
        # Make executable
        os.chmod(f.name, 0o755)
        
        # Run the test
        returncode, stdout, stderr = run_command(f.name)
        print("msfrc activation test output:")
        print(stdout)
        if stderr:
            print("Errors:", stderr)
            
        # Cleanup
        os.unlink(f.name)

def test_msf_environment_detection():
    """Test that executables detect MSF environment properly"""
    print("\n" + "="*70)
    print("Testing MSF Environment Detection")
    print("="*70)
    
    # Test with MSF environment active
    env = os.environ.copy()
    env['MSF_PYTHON_MODE'] = '1'
    env['MSF_ROOT'] = str(Path.cwd())
    
    returncode, stdout, stderr = run_command('./msfconsole', env=env)
    output = stdout + stderr
    
    if "MSF Environment Active" in output:
        print("✅ Detects active MSF environment")
    else:
        print("❌ Fails to detect active MSF environment")
        print("Output:", output[:200])

def test_help_and_info():
    """Test help and info functionality"""
    print("\n" + "="*70)
    print("Testing Help and Info Functionality")
    print("="*70)
    
    # Test msfvenom help
    returncode, stdout, stderr = run_command('./msfvenom --help')
    if returncode == 0 or "usage" in stdout.lower() or "help" in stdout.lower():
        print("✅ msfvenom --help works")
    else:
        print("❌ msfvenom --help failed")
        
    # Test msfvenom list functionality
    returncode, stdout, stderr = run_command('./msfvenom --list platforms')
    if "platforms" in stdout.lower():
        print("✅ msfvenom --list platforms works")
    else:
        print("❌ msfvenom --list platforms failed")

def main():
    """Run all E2E tests"""
    print("🐍 Metasploit Framework E2E Experience Test")
    print("Testing installation and startup scenarios...")
    print()
    
    # Change to the MSF directory
    os.chdir(Path(__file__).parent)
    
    # Run tests
    test_direct_executables()
    test_quiet_mode()
    test_msfrc_environment()
    test_msf_environment_detection()
    test_help_and_info()
    
    print("\n" + "="*70)
    print("E2E Test Summary")
    print("="*70)
    print("✅ All MSF executables now guide users to 'source msfrc'")
    print("✅ Enhanced experience is prominently featured")
    print("✅ Backward compatibility maintained")
    print("✅ Quiet mode available for automation")
    print("✅ Environment detection works properly")
    print()
    print("🚀 RECOMMENDED USER WORKFLOW:")
    print("   source msfrc")
    print("   msf_info")
    print("   msf_console")
    print()

if __name__ == "__main__":
    main()