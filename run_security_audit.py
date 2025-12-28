#!/usr/bin/env python3
"""
Security Audit Runner for Metasploit Framework
Runs the comprehensive security audit and generates a report
"""

import sys
import os
sys.path.insert(0, '/workspace/bak')

from security_audit import SecurityAuditor

def main():
    """Run security audit and display results"""
    print("Running comprehensive security audit...")
    
    auditor = SecurityAuditor('/workspace')
    report = auditor.run_full_audit()
    
    # Save report
    report_file = '/workspace/SECURITY_AUDIT_REPORT.md'
    with open(report_file, 'w', encoding='utf-8') as f:
        f.write(report)
    
    print(f"\nSecurity audit complete. Report saved to: {report_file}")
    print("\n" + "="*60)
    print("SECURITY AUDIT SUMMARY")
    print("="*60)
    
    # Display summary
    lines = report.split('\n')
    in_summary = False
    for line in lines:
        if '## Summary by Severity' in line:
            in_summary = True
            continue
        elif '## Detailed Issues' in line:
            break
        elif in_summary and line.strip():
            print(line)

if __name__ == "__main__":
    main()