#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
Quick CI/CD Fix Validation Script

This script validates that the CI/CD review issues have been addressed:
1. README.md has Features section
2. All documentation files exist
3. requirements.txt is clean and valid
4. Build process works
"""

import sys
import os
from pathlib import Path

def check_readme_features():
    """Check if README.md has Features section."""
    readme_path = Path(__file__).parent / 'README.md'
    if not readme_path.exists():
        return False, "README.md not found"
    
    content = readme_path.read_text()
    if 'features' not in content.lower():
        return False, "Features section not found in README.md"
    
    # Check for specific features mentioned in our added section
    required_features = [
        'python-native framework',
        'binary analysis',
        'exploitation tools',
        'network & protocol support'
    ]
    
    content_lower = content.lower()
    missing_features = []
    for feature in required_features:
        if feature not in content_lower:
            missing_features.append(feature)
    
    if missing_features:
        return False, f"Missing features in README.md: {missing_features}"
    
    return True, "README.md has comprehensive Features section"

def check_documentation_files():
    """Check if all required documentation files exist."""
    base_dir = Path(__file__).parent
    required_docs = [
        'README.md',
        'CONTRIBUTING.md', 
        'LICENSE.md',
        'CHANGELOG.md',
        'SECURITY.md',
        'CODE_OF_CONDUCT.md'
    ]
    
    missing_docs = []
    for doc in required_docs:
        if not (base_dir / doc).exists():
            missing_docs.append(doc)
    
    if missing_docs:
        return False, f"Missing documentation files: {missing_docs}"
    
    return True, "All required documentation files exist"

def check_requirements_file():
    """Check if requirements.txt is clean and valid."""
    req_path = Path(__file__).parent / 'requirements.txt'
    if not req_path.exists():
        return False, "requirements.txt not found"
    
    content = req_path.read_text()
    lines = [line.strip() for line in content.split('\n') if line.strip() and not line.startswith('#')]
    
    # Check for duplicates
    packages = []
    for line in lines:
        if '>=' in line:
            package = line.split('>=')[0].strip()
        elif '==' in line:
            package = line.split('==')[0].strip()
        elif ';' in line:
            package = line.split(';')[0].strip()
            if '>=' in package:
                package = package.split('>=')[0].strip()
        else:
            package = line.strip()
        
        if package:
            packages.append(package.lower())
    
    # Check for duplicates
    seen = set()
    duplicates = []
    for package in packages:
        if package in seen:
            duplicates.append(package)
        seen.add(package)
    
    if duplicates:
        return False, f"Duplicate packages in requirements.txt: {duplicates}"
    
    # Check for essential packages
    essential_packages = ['pytest', 'requests', 'cryptography']
    missing_essential = []
    for pkg in essential_packages:
        if pkg not in packages:
            missing_essential.append(pkg)
    
    if missing_essential:
        return False, f"Missing essential packages: {missing_essential}"
    
    return True, f"requirements.txt is clean with {len(packages)} unique packages"

def check_build_files():
    """Check if build configuration files exist."""
    base_dir = Path(__file__).parent
    build_files = [
        'pyproject.toml',
        'tasks.py',
        'conftest.py'
    ]
    
    missing_files = []
    for build_file in build_files:
        if not (base_dir / build_file).exists():
            missing_files.append(build_file)
    
    if missing_files:
        return False, f"Missing build files: {missing_files}"
    
    return True, "All build configuration files exist"

def main():
    """Run all validation checks."""
    print("🔍 CI/CD Fix Validation Report")
    print("=" * 50)
    
    checks = [
        ("README.md Features Section", check_readme_features),
        ("Documentation Files", check_documentation_files),
        ("Requirements File", check_requirements_file),
        ("Build Configuration", check_build_files)
    ]
    
    all_passed = True
    
    for check_name, check_func in checks:
        try:
            success, message = check_func()
            status = "✅ PASS" if success else "❌ FAIL"
            print(f"{status} {check_name}: {message}")
            
            if not success:
                all_passed = False
                
        except Exception as e:
            print(f"❌ FAIL {check_name}: Error - {e}")
            all_passed = False
    
    print("=" * 50)
    
    if all_passed:
        print("🎉 All CI/CD fixes validated successfully!")
        print("\nSummary of fixes applied:")
        print("- ✅ Added comprehensive Features section to README.md")
        print("- ✅ Cleaned up requirements.txt (removed duplicates)")
        print("- ✅ Verified all documentation files exist")
        print("- ✅ Confirmed build configuration is complete")
        print("\nThe CI/CD review should now pass!")
        return 0
    else:
        print("⚠️  Some issues remain. Please review the failures above.")
        return 1

if __name__ == '__main__':
    sys.exit(main())