#!/usr/bin/env python3
"""
Verification script to check GitHub Actions workflow permissions
Ensures all workflows that use write operations have proper permissions
"""

import os
import yaml
import re
from pathlib import Path

def check_workflow_permissions():
    """Check all workflow files for proper permissions"""
    workflows_dir = Path('/workspace/.github/workflows')
    issues_found = []
    
    # API operations that require write permissions
    write_operations = {
        'github.rest.issues.addAssignees': ['issues: write'],
        'github.rest.issues.createComment': ['issues: write'],
        'github.rest.issues.create': ['issues: write'],
        'github.rest.issues.addLabels': ['issues: write'],
        'github.rest.issues.update': ['issues: write'],
        'github.rest.issues.createLabel': ['issues: write'],
        'github.rest.pulls.create': ['pull-requests: write'],
        'github.rest.pulls.update': ['pull-requests: write'],
    }
    
    for workflow_file in workflows_dir.glob('*.yml'):
        if workflow_file.name.startswith('.'):
            continue
            
        print(f"Checking {workflow_file.name}...")
        
        try:
            with open(workflow_file, 'r') as f:
                content = f.read()
            
            # Check for write operations in the workflow
            operations_found = []
            for operation in write_operations.keys():
                if operation in content:
                    operations_found.append(operation)
            
            if not operations_found:
                print(f"  ✅ No write operations found")
                continue
            
            # Parse YAML to check permissions
            try:
                workflow_data = yaml.safe_load(content)
                permissions = workflow_data.get('permissions', {})
                
                if not permissions:
                    issues_found.append(f"{workflow_file.name}: Missing permissions section with operations: {operations_found}")
                    continue
                
                # Check if required permissions are present
                missing_permissions = []
                for operation in operations_found:
                    required_perms = write_operations[operation]
                    for perm in required_perms:
                        perm_key = perm.split(':')[0]
                        if perm_key not in permissions or permissions[perm_key] != 'write':
                            missing_permissions.append(perm)
                
                if missing_permissions:
                    issues_found.append(f"{workflow_file.name}: Missing permissions {missing_permissions} for operations: {operations_found}")
                else:
                    print(f"  ✅ Proper permissions found for operations: {operations_found}")
                    
            except yaml.YAMLError as e:
                issues_found.append(f"{workflow_file.name}: YAML parsing error: {e}")
                
        except Exception as e:
            issues_found.append(f"{workflow_file.name}: Error reading file: {e}")
    
    return issues_found

def main():
    """Main verification function"""
    print("🔍 GITHUB ACTIONS WORKFLOW PERMISSIONS VERIFICATION")
    print("=" * 60)
    
    issues = check_workflow_permissions()
    
    print("\n" + "=" * 60)
    print("📊 VERIFICATION RESULTS")
    print("=" * 60)
    
    if not issues:
        print("🎉 ALL WORKFLOWS HAVE PROPER PERMISSIONS!")
        print("\n✅ No permission issues found")
        print("✅ All workflows with write operations have appropriate permissions")
        return True
    else:
        print("⚠️  PERMISSION ISSUES FOUND:")
        for issue in issues:
            print(f"❌ {issue}")
        return False

if __name__ == "__main__":
    success = main()
    exit(0 if success else 1)