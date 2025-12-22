#!/usr/bin/env python3
"""
Security Audit Script for Metasploit Framework Python Migration

This script performs automated security checks on the transpiled codebase
to identify potential vulnerabilities and security issues.
"""

import os
import re
import sys
import ast
import subprocess
from pathlib import Path
from typing import List, Dict, Tuple, Set
import logging

class SecurityAuditor:
    """Automated security auditor for the Python migration"""
    
    def __init__(self, workspace_dir: str = "/workspace"):
        self.workspace_dir = Path(workspace_dir)
        self.issues = []
        self.setup_logging()
    
    def setup_logging(self):
        """Setup logging configuration"""
        logging.basicConfig(
            level=logging.INFO,
            format='%(asctime)s - %(levelname)s - %(message)s'
        )
        self.logger = logging.getLogger(__name__)
    
    def audit_malware_modules(self) -> List[Dict]:
        """Audit malware simulation modules for security issues"""
        self.logger.info("Auditing malware simulation modules...")
        malware_issues = []
        
        malware_dir = self.workspace_dir / "modules" / "malware"
        if not malware_dir.exists():
            return malware_issues
        
        for py_file in malware_dir.rglob("*.py"):
            issues = self.check_malware_file(py_file)
            malware_issues.extend(issues)
        
        return malware_issues
    
    def check_malware_file(self, file_path: Path) -> List[Dict]:
        """Check a specific malware file for security issues"""
        issues = []
        
        try:
            with open(file_path, 'r', encoding='utf-8') as f:
                content = f.read()
            
            # Check for dangerous system calls
            dangerous_calls = [
                'os.system', 'subprocess.call', 'subprocess.run',
                'eval(', 'exec(', 'compile(',
                'shell_command_token', 'insmod', 'rmmod'
            ]
            
            for call in dangerous_calls:
                if call in content:
                    issues.append({
                        'file': str(file_path),
                        'type': 'dangerous_call',
                        'severity': 'HIGH',
                        'description': f"Potentially dangerous call: {call}",
                        'line': self.find_line_number(content, call)
                    })
            
            # Check for hardcoded credentials or paths
            hardcoded_patterns = [
                r'password\s*=\s*["\'][^"\']+["\']',
                r'secret\s*=\s*["\'][^"\']+["\']',
                r'/workspace',
                r'127\.0\.0\.1',
                r'localhost'
            ]
            
            for pattern in hardcoded_patterns:
                matches = re.finditer(pattern, content, re.IGNORECASE)
                for match in matches:
                    issues.append({
                        'file': str(file_path),
                        'type': 'hardcoded_value',
                        'severity': 'MEDIUM',
                        'description': f"Hardcoded value found: {match.group()}",
                        'line': content[:match.start()].count('\n') + 1
                    })
            
            # Check for missing input validation
            if 'input(' in content or 'raw_input(' in content:
                issues.append({
                    'file': str(file_path),
                    'type': 'input_validation',
                    'severity': 'MEDIUM',
                    'description': "User input without apparent validation",
                    'line': self.find_line_number(content, 'input(')
                })
        
        except Exception as e:
            self.logger.error(f"Error checking {file_path}: {e}")
        
        return issues
    
    def audit_path_injection(self) -> List[Dict]:
        """Audit for path injection vulnerabilities"""
        self.logger.info("Auditing for path injection vulnerabilities...")
        path_issues = []
        
        for py_file in self.workspace_dir.rglob("*.py"):
            try:
                with open(py_file, 'r', encoding='utf-8') as f:
                    content = f.read()
                
                # Check for sys.path manipulation
                if 'sys.path.insert' in content:
                    path_issues.append({
                        'file': str(py_file),
                        'type': 'path_injection',
                        'severity': 'HIGH',
                        'description': "Unsafe sys.path manipulation",
                        'line': self.find_line_number(content, 'sys.path.insert')
                    })
                
                # Check for os.path.join with user input
                if re.search(r'os\.path\.join\([^)]*input\([^)]*\)', content):
                    path_issues.append({
                        'file': str(py_file),
                        'type': 'path_traversal',
                        'severity': 'HIGH',
                        'description': "Potential path traversal vulnerability",
                        'line': self.find_line_number(content, 'os.path.join')
                    })
            
            except Exception as e:
                continue
        
        return path_issues
    
    def audit_import_security(self) -> List[Dict]:
        """Audit import statements for security issues"""
        self.logger.info("Auditing import security...")
        import_issues = []
        
        dangerous_imports = [
            'pickle', 'cPickle', 'marshal', 'shelve',
            'subprocess', 'os', 'sys'
        ]
        
        for py_file in self.workspace_dir.rglob("*.py"):
            try:
                with open(py_file, 'r', encoding='utf-8') as f:
                    content = f.read()
                
                # Parse AST to check imports
                try:
                    tree = ast.parse(content)
                    for node in ast.walk(tree):
                        if isinstance(node, ast.Import):
                            for alias in node.names:
                                if alias.name in dangerous_imports:
                                    import_issues.append({
                                        'file': str(py_file),
                                        'type': 'dangerous_import',
                                        'severity': 'MEDIUM',
                                        'description': f"Potentially dangerous import: {alias.name}",
                                        'line': node.lineno
                                    })
                        
                        elif isinstance(node, ast.ImportFrom):
                            if node.module in dangerous_imports:
                                import_issues.append({
                                    'file': str(py_file),
                                    'type': 'dangerous_import',
                                    'severity': 'MEDIUM',
                                    'description': f"Potentially dangerous import from: {node.module}",
                                    'line': node.lineno
                                })
                except SyntaxError:
                    # Skip files with syntax errors
                    continue
            
            except Exception as e:
                continue
        
        return import_issues
    
    def audit_dependency_security(self) -> List[Dict]:
        """Audit Python dependencies for known vulnerabilities"""
        self.logger.info("Auditing dependency security...")
        dep_issues = []
        
        requirements_file = self.workspace_dir / "requirements.txt"
        if not requirements_file.exists():
            return dep_issues
        
        try:
            # Use safety to check for known vulnerabilities
            result = subprocess.run([
                sys.executable, '-m', 'pip', 'install', 'safety'
            ], capture_output=True, text=True)
            
            if result.returncode == 0:
                # Run safety check
                safety_result = subprocess.run([
                    sys.executable, '-m', 'safety', 'check', 
                    '--file', str(requirements_file)
                ], capture_output=True, text=True)
                
                if safety_result.returncode != 0:
                    dep_issues.append({
                        'file': str(requirements_file),
                        'type': 'vulnerable_dependency',
                        'severity': 'HIGH',
                        'description': "Vulnerable dependencies found",
                        'details': safety_result.stdout
                    })
        
        except Exception as e:
            self.logger.warning(f"Could not run dependency security check: {e}")
        
        return dep_issues
    
    def find_line_number(self, content: str, search_term: str) -> int:
        """Find line number of a search term in content"""
        lines = content.split('\n')
        for i, line in enumerate(lines):
            if search_term in line:
                return i + 1
        return 0
    
    def generate_report(self, all_issues: List[Dict]) -> str:
        """Generate a security audit report"""
        report = """# Security Audit Report
## Metasploit Framework Python Migration

**Audit Date:** {date}
**Total Issues Found:** {total}

## Summary by Severity

"""
        
        from datetime import datetime
        
        # Count issues by severity
        severity_counts = {}
        for issue in all_issues:
            severity = issue.get('severity', 'UNKNOWN')
            severity_counts[severity] = severity_counts.get(severity, 0) + 1
        
        for severity, count in sorted(severity_counts.items()):
            report += f"- **{severity}:** {count} issues\n"
        
        report += "\n## Detailed Issues\n\n"
        
        # Group issues by type
        issues_by_type = {}
        for issue in all_issues:
            issue_type = issue.get('type', 'unknown')
            if issue_type not in issues_by_type:
                issues_by_type[issue_type] = []
            issues_by_type[issue_type].append(issue)
        
        for issue_type, issues in issues_by_type.items():
            report += f"### {issue_type.replace('_', ' ').title()}\n\n"
            
            for issue in issues:
                report += f"**File:** `{issue['file']}`\n"
                report += f"**Severity:** {issue['severity']}\n"
                report += f"**Description:** {issue['description']}\n"
                if 'line' in issue:
                    report += f"**Line:** {issue['line']}\n"
                if 'details' in issue:
                    report += f"**Details:**\n```\n{issue['details']}\n```\n"
                report += "\n---\n\n"
        
        return report.format(
            date=datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
            total=len(all_issues)
        )
    
    def run_full_audit(self) -> str:
        """Run complete security audit"""
        self.logger.info("Starting comprehensive security audit...")
        
        all_issues = []
        
        # Run all audit checks
        all_issues.extend(self.audit_malware_modules())
        all_issues.extend(self.audit_path_injection())
        all_issues.extend(self.audit_import_security())
        all_issues.extend(self.audit_dependency_security())
        
        # Generate report
        report = self.generate_report(all_issues)
        
        self.logger.info(f"Security audit complete. Found {len(all_issues)} issues.")
        
        return report

def main():
    """Main execution function"""
    auditor = SecurityAuditor()
    report = auditor.run_full_audit()
    
    # Save report
    report_file = Path("/workspace/SECURITY_AUDIT_REPORT.md")
    with open(report_file, 'w', encoding='utf-8') as f:
        f.write(report)
    
    print(f"Security audit complete. Report saved to: {report_file}")
    print("\nSummary:")
    print(report.split("## Detailed Issues")[0])

if __name__ == "__main__":
    main()