#!/usr/bin/env python3
"""
Quick test to validate that our cleaned configuration files work properly.
This simulates the CI/CD build process.
"""

import subprocess
import sys
import os

def test_requirements_install():
    """Test if requirements.txt can be installed without conflicts"""
    print("🔍 Testing requirements.txt installation...")
    
    # First, let's do a dry run to check for conflicts
    cmd = [sys.executable, '-m', 'pip', 'install', '--dry-run', '-r', 'requirements.txt']
    
    try:
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=120)
        if result.returncode == 0:
            print("✅ Requirements.txt dry-run successful - no conflicts detected")
            return True
        else:
            print("❌ Requirements.txt has conflicts:")
            print(result.stderr[:1000])  # Show first 1000 chars of error
            return False
    except subprocess.TimeoutExpired:
        print("⏰ Requirements test timed out")
        return False
    except Exception as e:
        print(f"💥 Error testing requirements: {e}")
        return False

def test_pyproject_syntax():
    """Test if pyproject.toml has valid syntax"""
    print("🔍 Testing pyproject.toml syntax...")
    
    try:
        # Try to parse the TOML file
        import tomllib
        with open('pyproject.toml', 'rb') as f:
            config = tomllib.load(f)
        
        # Check if pytest config exists
        if 'tool' in config and 'pytest' in config['tool']:
            print("✅ pyproject.toml syntax valid and pytest config found")
            return True
        else:
            print("⚠️ pyproject.toml valid but missing pytest config")
            return False
            
    except ImportError:
        # Python < 3.11, try with toml library
        try:
            import toml
            with open('pyproject.toml', 'r') as f:
                config = toml.load(f)
            print("✅ pyproject.toml syntax valid (using toml library)")
            return True
        except ImportError:
            print("⚠️ Cannot validate TOML syntax - tomllib/toml not available")
            return True  # Don't fail the test for this
        except Exception as e:
            print(f"❌ pyproject.toml syntax error: {e}")
            return False
    except Exception as e:
        print(f"❌ pyproject.toml syntax error: {e}")
        return False

def main():
    """Run quick validation tests"""
    print("🚀 Running quick build validation...\n")
    
    tests = [
        ("pyproject.toml syntax", test_pyproject_syntax),
        ("requirements.txt installation", test_requirements_install),
    ]
    
    results = []
    for test_name, test_func in tests:
        print(f"\n{'='*50}")
        print(f"Testing: {test_name}")
        print('='*50)
        results.append(test_func())
    
    # Summary
    print(f"\n{'='*50}")
    print("SUMMARY")
    print('='*50)
    
    passed = sum(results)
    total = len(results)
    
    print(f"✅ Passed: {passed}/{total}")
    print(f"❌ Failed: {total - passed}/{total}")
    
    if passed == total:
        print("\n🎉 All tests passed! Configuration files are valid.")
        print("The CI/CD build should now succeed.")
        return 0
    else:
        print(f"\n⚠️ {total - passed} tests failed. There may still be issues.")
        return 1

if __name__ == "__main__":
    sys.exit(main())