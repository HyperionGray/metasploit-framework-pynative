#!/usr/bin/env python3
"""
Comprehensive Security Scanning Script for Amazon Q Code Review
Integrates multiple security tools for credential scanning, vulnerability detection,
and code injection risk assessment.
"""

import json
import os
import subprocess
import sys
import tempfile
from datetime import datetime
from pathlib import Path
from typing import Dict, List, Any, Optional
import argparse


class SecurityScanner:
    """Comprehensive security scanner for the Metasploit Framework repository."""
    
    def __init__(self, repo_path: str = "."):
        self.repo_path = Path(repo_path)
        self.results = {}
        self.timestamp = datetime.utcnow().isoformat()
        
    def run_command(self, cmd: List[str], capture_output: bool = True) -> Dict[str, Any]:
        """Run a command and return results with error handling."""
        try:
            result = subprocess.run(
                cmd, 
                capture_output=capture_output, 
                text=True, 
                cwd=self.repo_path,
                timeout=300  # 5 minute timeout
            )
            return {
                "success": result.returncode == 0,
                "stdout": result.stdout,
                "stderr": result.stderr,
                "returncode": result.returncode
            }
        except subprocess.TimeoutExpired:
            return {
                "success": False,
                "stdout": "",
                "stderr": "Command timed out after 5 minutes",
                "returncode": -1
            }
        except Exception as e:
            return {
                "success": False,
                "stdout": "",
                "stderr": str(e),
                "returncode": -1
            }
    
    def scan_credentials(self) -> Dict[str, Any]:
        """Scan for hardcoded credentials using detect-secrets."""
        print("🔍 Scanning for hardcoded credentials...")
        
        # Check if detect-secrets is available
        check_cmd = ["python3", "-m", "detect_secrets", "--version"]
        check_result = self.run_command(check_cmd)
        
        if not check_result["success"]:
            return {
                "tool": "detect-secrets",
                "status": "not_available",
                "message": "detect-secrets not installed. Install with: pip install detect-secrets",
                "findings": []
            }
        
        # Run detect-secrets scan
        scan_cmd = [
            "python3", "-m", "detect_secrets", "scan",
            "--baseline", ".secrets.baseline",
            "--force-use-all-plugins",
            "--exclude-files", r".*\.lock$",
            "--exclude-files", r".*\.log$", 
            "--exclude-files", r".*/test/.*",
            "--exclude-files", r".*/tests/.*",
            "--exclude-files", r".*/data/wordlists/.*",
            "--exclude-files", r".*/modules_legacy/.*"
        ]
        
        result = self.run_command(scan_cmd)
        
        if result["success"]:
            try:
                findings = json.loads(result["stdout"])
                return {
                    "tool": "detect-secrets",
                    "status": "success",
                    "findings": findings.get("results", {}),
                    "summary": f"Scanned {len(findings.get('results', {}))} files"
                }
            except json.JSONDecodeError:
                return {
                    "tool": "detect-secrets",
                    "status": "parse_error",
                    "message": "Failed to parse detect-secrets output",
                    "raw_output": result["stdout"][:1000]
                }
        else:
            return {
                "tool": "detect-secrets",
                "status": "error",
                "message": result["stderr"],
                "findings": []
            }
    
    def scan_bandit(self) -> Dict[str, Any]:
        """Run bandit security analysis."""
        print("🛡️  Running bandit security analysis...")
        
        cmd = [
            "bandit", "-r", "lib/", "python_framework/", "modules/",
            "-f", "json",
            "-c", ".bandit"
        ]
        
        result = self.run_command(cmd)
        
        if result["returncode"] in [0, 1]:  # 0 = no issues, 1 = issues found
            try:
                findings = json.loads(result["stdout"])
                return {
                    "tool": "bandit",
                    "status": "success",
                    "findings": findings,
                    "summary": f"Found {len(findings.get('results', []))} security issues"
                }
            except json.JSONDecodeError:
                return {
                    "tool": "bandit",
                    "status": "parse_error",
                    "message": "Failed to parse bandit output",
                    "raw_output": result["stdout"][:1000]
                }
        else:
            return {
                "tool": "bandit",
                "status": "error",
                "message": result["stderr"],
                "findings": {}
            }
    
    def scan_safety(self) -> Dict[str, Any]:
        """Run safety dependency vulnerability scan."""
        print("📦 Scanning dependencies for vulnerabilities...")
        
        cmd = ["safety", "check", "--json"]
        result = self.run_command(cmd)
        
        if result["returncode"] in [0, 64]:  # 0 = no vulns, 64 = vulns found
            try:
                if result["stdout"].strip():
                    findings = json.loads(result["stdout"])
                else:
                    findings = []
                    
                return {
                    "tool": "safety",
                    "status": "success",
                    "findings": findings,
                    "summary": f"Found {len(findings)} vulnerable dependencies"
                }
            except json.JSONDecodeError:
                return {
                    "tool": "safety",
                    "status": "parse_error",
                    "message": "Failed to parse safety output",
                    "raw_output": result["stdout"][:1000]
                }
        else:
            return {
                "tool": "safety",
                "status": "error",
                "message": result["stderr"],
                "findings": []
            }
    
    def scan_pip_audit(self) -> Dict[str, Any]:
        """Run pip-audit for additional vulnerability scanning."""
        print("🔍 Running pip-audit vulnerability scan...")
        
        # Check if pip-audit is available
        check_cmd = ["pip-audit", "--version"]
        check_result = self.run_command(check_cmd)
        
        if not check_result["success"]:
            return {
                "tool": "pip-audit",
                "status": "not_available",
                "message": "pip-audit not installed. Install with: pip install pip-audit",
                "findings": []
            }
        
        cmd = ["pip-audit", "--format=json", "--desc"]
        result = self.run_command(cmd)
        
        if result["success"]:
            try:
                findings = json.loads(result["stdout"])
                return {
                    "tool": "pip-audit",
                    "status": "success",
                    "findings": findings,
                    "summary": f"Scanned dependencies for vulnerabilities"
                }
            except json.JSONDecodeError:
                return {
                    "tool": "pip-audit",
                    "status": "parse_error",
                    "message": "Failed to parse pip-audit output",
                    "raw_output": result["stdout"][:1000]
                }
        else:
            return {
                "tool": "pip-audit",
                "status": "error",
                "message": result["stderr"],
                "findings": []
            }
    
    def analyze_code_injection_risks(self) -> Dict[str, Any]:
        """Analyze code for potential injection vulnerabilities."""
        print("💉 Analyzing code injection risks...")
        
        injection_patterns = {
            "sql_injection": [
                r"execute\s*\(\s*[\"'].*%.*[\"']",
                r"cursor\.execute\s*\(\s*[\"'].*\+.*[\"']",
                r"query\s*=\s*[\"'].*%.*[\"']",
                r"SELECT.*\+.*FROM",
                r"INSERT.*\+.*VALUES"
            ],
            "command_injection": [
                r"os\.system\s*\(\s*.*\+",
                r"subprocess\.(call|run|Popen).*shell=True.*\+",
                r"eval\s*\(",
                r"exec\s*\(",
                r"__import__\s*\("
            ],
            "path_traversal": [
                r"open\s*\(\s*.*\+.*[\"']\.\./",
                r"file\s*=\s*.*\+.*[\"']\.\./",
                r"path\s*=\s*.*\+.*[\"']\.\./",
                r"\.\./"
            ]
        }
        
        findings = {}
        
        # Search for injection patterns in Python files
        python_files = list(self.repo_path.rglob("*.py"))
        
        for category, patterns in injection_patterns.items():
            findings[category] = []
            
            for pattern in patterns:
                cmd = ["grep", "-rn", "-E", pattern, "--include=*.py", "."]
                result = self.run_command(cmd)
                
                if result["success"] and result["stdout"]:
                    matches = result["stdout"].strip().split('\n')
                    for match in matches:
                        if match and not any(exclude in match for exclude in ["/test/", "/tests/", "/spec/", "modules_legacy/"]):
                            findings[category].append({
                                "pattern": pattern,
                                "match": match,
                                "risk_level": "medium"
                            })
        
        total_findings = sum(len(findings[cat]) for cat in findings)
        
        return {
            "tool": "code_injection_analysis",
            "status": "success",
            "findings": findings,
            "summary": f"Found {total_findings} potential injection risks"
        }
    
    def run_comprehensive_scan(self) -> Dict[str, Any]:
        """Run all security scans and compile results."""
        print("🚀 Starting comprehensive security scan...")
        
        self.results = {
            "scan_info": {
                "timestamp": self.timestamp,
                "repository": str(self.repo_path),
                "scanner_version": "1.0.0"
            },
            "scans": {}
        }
        
        # Run all security scans
        scan_functions = [
            ("credential_scan", self.scan_credentials),
            ("bandit_scan", self.scan_bandit),
            ("safety_scan", self.scan_safety),
            ("pip_audit_scan", self.scan_pip_audit),
            ("injection_analysis", self.analyze_code_injection_risks)
        ]
        
        for scan_name, scan_func in scan_functions:
            try:
                self.results["scans"][scan_name] = scan_func()
            except Exception as e:
                self.results["scans"][scan_name] = {
                    "tool": scan_name,
                    "status": "error",
                    "message": f"Scan failed: {str(e)}",
                    "findings": []
                }
        
        # Generate summary
        self.results["summary"] = self.generate_summary()
        
        return self.results
    
    def generate_summary(self) -> Dict[str, Any]:
        """Generate a summary of all scan results."""
        summary = {
            "total_scans": len(self.results["scans"]),
            "successful_scans": 0,
            "failed_scans": 0,
            "total_findings": 0,
            "high_priority_findings": 0,
            "recommendations": []
        }
        
        for scan_name, scan_result in self.results["scans"].items():
            if scan_result["status"] == "success":
                summary["successful_scans"] += 1
                
                # Count findings
                findings = scan_result.get("findings", [])
                if isinstance(findings, dict):
                    if scan_name == "injection_analysis":
                        summary["total_findings"] += sum(len(findings[cat]) for cat in findings)
                    else:
                        summary["total_findings"] += len(findings.get("results", []))
                elif isinstance(findings, list):
                    summary["total_findings"] += len(findings)
            else:
                summary["failed_scans"] += 1
        
        # Generate recommendations
        if summary["total_findings"] > 0:
            summary["recommendations"].extend([
                "Review and address security findings by priority",
                "Implement secure coding practices",
                "Add security testing to CI/CD pipeline",
                "Regular dependency updates and vulnerability scanning"
            ])
        
        return summary
    
    def save_results(self, output_file: str = "security_scan_results.json"):
        """Save scan results to a JSON file."""
        output_path = self.repo_path / output_file
        with open(output_path, 'w') as f:
            json.dump(self.results, f, indent=2)
        print(f"📄 Results saved to {output_path}")


def main():
    parser = argparse.ArgumentParser(description="Comprehensive Security Scanner for Amazon Q Code Review")
    parser.add_argument("--repo-path", default=".", help="Path to repository to scan")
    parser.add_argument("--output", default="security_scan_results.json", help="Output file for results")
    parser.add_argument("--verbose", action="store_true", help="Verbose output")
    
    args = parser.parse_args()
    
    scanner = SecurityScanner(args.repo_path)
    results = scanner.run_comprehensive_scan()
    scanner.save_results(args.output)
    
    # Print summary
    summary = results["summary"]
    print("\n" + "="*50)
    print("🔒 SECURITY SCAN SUMMARY")
    print("="*50)
    print(f"Total scans: {summary['total_scans']}")
    print(f"Successful: {summary['successful_scans']}")
    print(f"Failed: {summary['failed_scans']}")
    print(f"Total findings: {summary['total_findings']}")
    
    if summary["recommendations"]:
        print("\n📋 RECOMMENDATIONS:")
        for i, rec in enumerate(summary["recommendations"], 1):
            print(f"{i}. {rec}")
    
    # Exit with appropriate code
    if summary["failed_scans"] > 0:
        sys.exit(1)
    elif summary["total_findings"] > 0:
        sys.exit(2)  # Findings found but scan successful
    else:
        sys.exit(0)  # All clean


if __name__ == "__main__":
    main()