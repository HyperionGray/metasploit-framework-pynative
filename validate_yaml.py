#!/usr/bin/env python3
"""
Simple YAML validation script to check GitHub Actions workflow files
"""

import yaml
import sys
from pathlib import Path

def validate_yaml_file(file_path):
    """Validate a YAML file and return any errors"""
    try:
        with open(file_path, 'r', encoding='utf-8') as f:
            yaml.safe_load(f)
        return True, None
    except yaml.YAMLError as e:
        return False, str(e)
    except Exception as e:
        return False, f"Error reading file: {e}"

def main():
    """Validate the modified workflow files"""
    workflow_files = [
        '/workspace/.github/workflows/auto-gpt5-implementation.yml',
        '/workspace/.github/workflows/auto-copilot-functionality-docs-review.yml'
    ]
    
    print("🔍 Validating GitHub Actions workflow YAML syntax...")
    print("=" * 60)
    
    all_valid = True
    
    for file_path in workflow_files:
        file_path = Path(file_path)
        if not file_path.exists():
            print(f"❌ {file_path.name}: File not found")
            all_valid = False
            continue
            
        is_valid, error = validate_yaml_file(file_path)
        
        if is_valid:
            print(f"✅ {file_path.name}: Valid YAML syntax")
        else:
            print(f"❌ {file_path.name}: YAML syntax error")
            print(f"   Error: {error}")
            all_valid = False
    
    print("=" * 60)
    
    if all_valid:
        print("🎉 All workflow files have valid YAML syntax!")
        print("✅ CI pipeline should now run without 'repository not found' errors")
        return 0
    else:
        print("❌ Some workflow files have YAML syntax errors")
        print("⚠️  Please fix the errors before committing")
        return 1

if __name__ == '__main__':
    sys.exit(main())