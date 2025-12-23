#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Test script to verify Metasploit Framework Python configuration and basic functionality.
"""

import sys
from pathlib import Path

# Add MSF root to path
msf_root = Path(__file__).resolve().parent
sys.path.insert(0, str(msf_root))

def test_config_imports():
    """Test that all config modules can be imported"""
    print("Testing config imports...")
    try:
        from config import boot, application, environment
        print("✓ All config modules imported successfully")
        return True
    except Exception as e:
        print(f"✗ Config import failed: {e}")
        return False

def test_boot_config():
    """Test boot configuration"""
    print("\nTesting boot configuration...")
    try:
        from config import boot
        config = boot.setup_environment()
        assert config['msf_root'] == msf_root
        print(f"✓ Boot config OK - MSF_ROOT: {config['msf_root']}")
        return True
    except Exception as e:
        print(f"✗ Boot config failed: {e}")
        return False

def test_application_config():
    """Test application configuration"""
    print("\nTesting application configuration...")
    try:
        from config import application
        config = application.get_config()
        config_dict = config.to_dict()
        print(f"✓ Application config OK")
        print(f"  - MSF Root: {config_dict['msf_root']}")
        print(f"  - Module paths: {len(config_dict['module_paths'])} configured")
        print(f"  - Cache dir: {config_dict['cache_dir']}")
        return True
    except Exception as e:
        print(f"✗ Application config failed: {e}")
        return False

def test_environment_config():
    """Test environment configuration"""
    print("\nTesting environment configuration...")
    try:
        from config import environment
        assert environment.MSF_ROOT == msf_root
        print(f"✓ Environment config OK - MSF_ROOT: {environment.MSF_ROOT}")
        return True
    except Exception as e:
        print(f"✗ Environment config failed: {e}")
        return False

def test_msfrc_exists():
    """Test that msfrc file exists and is executable"""
    print("\nTesting msfrc file...")
    try:
        msfrc = msf_root / 'msfrc'
        if not msfrc.exists():
            print(f"✗ msfrc file not found at {msfrc}")
            return False
        if not msfrc.stat().st_mode & 0o111:
            print(f"✗ msfrc is not executable")
            return False
        print(f"✓ msfrc exists and is executable at {msfrc}")
        return True
    except Exception as e:
        print(f"✗ msfrc check failed: {e}")
        return False

def test_transpilers_exist():
    """Test that transpiler tools exist in new location"""
    print("\nTesting transpiler organization...")
    try:
        ruby2py = msf_root / 'transpilers' / 'ruby2py' / 'converter.py'
        py2ruby = msf_root / 'transpilers' / 'py2ruby' / 'transpiler.py'
        
        if not ruby2py.exists():
            print(f"✗ Ruby to Python converter not found at {ruby2py}")
            return False
        if not py2ruby.exists():
            print(f"✗ Python to Ruby transpiler not found at {py2ruby}")
            return False
        
        print(f"✓ Transpilers organized correctly")
        print(f"  - ruby2py: {ruby2py}")
        print(f"  - py2ruby: {py2ruby}")
        return True
    except Exception as e:
        print(f"✗ Transpiler check failed: {e}")
        return False

def test_documentation():
    """Test that documentation is organized"""
    print("\nTesting documentation organization...")
    try:
        docs_dir = msf_root / 'docs'
        documentation_dir = msf_root / 'documentation'
        transpilers_readme = msf_root / 'transpilers' / 'README.md'
        
        if not docs_dir.exists():
            print(f"✗ docs/ directory not found")
            return False
        if not documentation_dir.exists():
            print(f"✗ documentation/ directory not found")
            return False
        if not transpilers_readme.exists():
            print(f"✗ transpilers/README.md not found")
            return False
        
        print(f"✓ Documentation organized correctly")
        print(f"  - docs/: {docs_dir}")
        print(f"  - documentation/: {documentation_dir}")
        print(f"  - transpilers/README.md: {transpilers_readme}")
        return True
    except Exception as e:
        print(f"✗ Documentation check failed: {e}")
        return False

def main():
    """Run all tests"""
    print("="*70)
    print("Metasploit Framework Configuration Test Suite")
    print("="*70)
    
    tests = [
        test_config_imports,
        test_boot_config,
        test_application_config,
        test_environment_config,
        test_msfrc_exists,
        test_transpilers_exist,
        test_documentation,
    ]
    
    results = []
    for test in tests:
        try:
            results.append(test())
        except Exception as e:
            print(f"✗ Test {test.__name__} failed with exception: {e}")
            results.append(False)
    
    print("\n" + "="*70)
    print("Test Results")
    print("="*70)
    passed = sum(results)
    total = len(results)
    print(f"Passed: {passed}/{total}")
    
    if passed == total:
        print("\n✓ All tests passed! Configuration is working correctly.")
        return 0
    else:
        print(f"\n✗ {total - passed} test(s) failed.")
        return 1

if __name__ == '__main__':
    sys.exit(main())
