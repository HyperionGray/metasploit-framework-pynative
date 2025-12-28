#!/usr/bin/env python3
"""
Build Validation Script for Metasploit Framework Python-native

This script provides comprehensive build validation with detailed error reporting
to replace the ambiguous "Build result: false" status.
"""

import sys
import os
import subprocess
import importlib.util
from pathlib import Path
from typing import List, Dict, Tuple, Optional
import json
import time
from datetime import datetime


class BuildValidator:
    """Comprehensive build validation for the Metasploit Framework."""
    
    def __init__(self):
        self.results = {
            'timestamp': datetime.utcnow().isoformat(),
            'overall_status': 'UNKNOWN',
            'checks': {},
            'errors': [],
            'warnings': [],
            'summary': {}
        }
        self.root_path = Path(__file__).parent
        
    def log_result(self, check_name: str, status: str, message: str, details: Optional[Dict] = None):
        """Log a check result."""
        self.results['checks'][check_name] = {
            'status': status,
            'message': message,
            'details': details or {}
        }
        
        if status == 'FAIL':
            self.results['errors'].append(f"{check_name}: {message}")
        elif status == 'WARN':
            self.results['warnings'].append(f"{check_name}: {message}")
            
        print(f"[{status}] {check_name}: {message}")
        
    def check_python_version(self) -> bool:
        """Check Python version compatibility."""
        version = sys.version_info
        if version.major == 3 and version.minor >= 8:
            self.log_result('python_version', 'PASS', 
                          f"Python {version.major}.{version.minor}.{version.micro} is compatible")
            return True
        else:
            self.log_result('python_version', 'FAIL', 
                          f"Python {version.major}.{version.minor}.{version.micro} is not supported (requires 3.8+)")
            return False
            
    def check_configuration_files(self) -> bool:
        """Check that essential configuration files exist and are valid."""
        config_files = {
            'pyproject.toml': 'Build configuration',
            'requirements.txt': 'Python dependencies',
            'README.md': 'Project documentation',
            'LICENSE.md': 'License information',
            'CONTRIBUTING.md': 'Contribution guidelines'
        }
        
        all_good = True
        for file_name, description in config_files.items():
            file_path = self.root_path / file_name
            if file_path.exists():
                try:
                    content = file_path.read_text(encoding='utf-8')
                    if len(content.strip()) > 0:
                        self.log_result(f'config_{file_name}', 'PASS', 
                                      f"{description} exists and has content")
                    else:
                        self.log_result(f'config_{file_name}', 'WARN', 
                                      f"{description} exists but is empty")
                        all_good = False
                except Exception as e:
                    self.log_result(f'config_{file_name}', 'FAIL', 
                                  f"Error reading {description}: {e}")
                    all_good = False
            else:
                self.log_result(f'config_{file_name}', 'FAIL', 
                              f"{description} is missing")
                all_good = False
                
        return all_good
        
    def check_dependencies(self) -> bool:
        """Check that critical dependencies can be imported."""
        critical_deps = [
            'pytest',
            'requests',
            'cryptography',
            'pyyaml',
            'flask'
        ]
        
        all_good = True
        for dep in critical_deps:
            try:
                importlib.import_module(dep)
                self.log_result(f'dep_{dep}', 'PASS', f"Dependency {dep} is available")
            except ImportError as e:
                self.log_result(f'dep_{dep}', 'FAIL', f"Dependency {dep} is missing: {e}")
                all_good = False
                
        return all_good
        
    def check_framework_structure(self) -> bool:
        """Check that the framework directory structure is correct."""
        required_dirs = [
            'lib',
            'modules',
            'python_framework',
            'test',
            'data'
        ]
        
        all_good = True
        for dir_name in required_dirs:
            dir_path = self.root_path / dir_name
            if dir_path.exists() and dir_path.is_dir():
                self.log_result(f'structure_{dir_name}', 'PASS', 
                              f"Directory {dir_name} exists")
            else:
                self.log_result(f'structure_{dir_name}', 'FAIL', 
                              f"Required directory {dir_name} is missing")
                all_good = False
                
        return all_good
        
    def check_core_imports(self) -> bool:
        """Check that core framework modules can be imported."""
        core_modules = [
            'python_framework.core.exploit',
            'python_framework.helpers.http_client'
        ]
        
        # Add python_framework to path
        sys.path.insert(0, str(self.root_path / 'python_framework'))
        sys.path.insert(0, str(self.root_path))
        
        all_good = True
        for module_name in core_modules:
            try:
                parts = module_name.split('.')
                if len(parts) > 1:
                    module = importlib.import_module(module_name)
                else:
                    module = importlib.import_module(module_name)
                    
                self.log_result(f'import_{module_name}', 'PASS', 
                              f"Core module {module_name} imports successfully")
            except ImportError as e:
                self.log_result(f'import_{module_name}', 'FAIL', 
                              f"Core module {module_name} failed to import: {e}")
                all_good = False
            except Exception as e:
                self.log_result(f'import_{module_name}', 'FAIL', 
                              f"Unexpected error importing {module_name}: {e}")
                all_good = False
                
        return all_good
        
    def check_test_discovery(self) -> bool:
        """Check that tests can be discovered."""
        try:
            result = subprocess.run([
                sys.executable, '-m', 'pytest', '--collect-only', '-q'
            ], capture_output=True, text=True, cwd=self.root_path, timeout=30)
            
            if result.returncode == 0:
                lines = result.stdout.strip().split('\n')
                test_count = len([line for line in lines if '::' in line])
                self.log_result('test_discovery', 'PASS', 
                              f"Test discovery successful, found {test_count} tests")
                return True
            else:
                self.log_result('test_discovery', 'FAIL', 
                              f"Test discovery failed: {result.stderr}")
                return False
                
        except subprocess.TimeoutExpired:
            self.log_result('test_discovery', 'FAIL', 
                          "Test discovery timed out after 30 seconds")
            return False
        except Exception as e:
            self.log_result('test_discovery', 'FAIL', 
                          f"Test discovery error: {e}")
            return False
            
    def check_linting(self) -> bool:
        """Check code quality with basic linting."""
        try:
            # Check if flake8 is available and run basic check
            result = subprocess.run([
                sys.executable, '-m', 'flake8', '--version'
            ], capture_output=True, text=True, timeout=10)
            
            if result.returncode == 0:
                # Run flake8 on a small subset to test
                lint_result = subprocess.run([
                    sys.executable, '-m', 'flake8', 'python_framework/', '--count', '--max-line-length=120'
                ], capture_output=True, text=True, cwd=self.root_path, timeout=30)
                
                if lint_result.returncode == 0:
                    self.log_result('linting', 'PASS', "Code linting passed")
                    return True
                else:
                    error_count = lint_result.stdout.strip().split('\n')[-1] if lint_result.stdout else "unknown"
                    self.log_result('linting', 'WARN', 
                                  f"Linting found issues: {error_count}")
                    return True  # Don't fail build for linting issues
            else:
                self.log_result('linting', 'WARN', "Flake8 not available for linting check")
                return True
                
        except Exception as e:
            self.log_result('linting', 'WARN', f"Linting check error: {e}")
            return True  # Don't fail build for linting issues
            
    def run_sample_test(self) -> bool:
        """Run a small sample of tests to verify test execution."""
        try:
            result = subprocess.run([
                sys.executable, '-m', 'pytest', 
                'test/test_comprehensive_suite.py::TestFrameworkCore::test_framework_imports',
                '-v', '--tb=short'
            ], capture_output=True, text=True, cwd=self.root_path, timeout=60)
            
            if result.returncode == 0:
                self.log_result('sample_test', 'PASS', "Sample test execution successful")
                return True
            else:
                self.log_result('sample_test', 'FAIL', 
                              f"Sample test failed: {result.stderr}")
                return False
                
        except subprocess.TimeoutExpired:
            self.log_result('sample_test', 'FAIL', 
                          "Sample test timed out after 60 seconds")
            return False
        except Exception as e:
            self.log_result('sample_test', 'FAIL', 
                          f"Sample test error: {e}")
            return False
            
    def generate_summary(self):
        """Generate build summary."""
        total_checks = len(self.results['checks'])
        passed = len([c for c in self.results['checks'].values() if c['status'] == 'PASS'])
        failed = len([c for c in self.results['checks'].values() if c['status'] == 'FAIL'])
        warned = len([c for c in self.results['checks'].values() if c['status'] == 'WARN'])
        
        self.results['summary'] = {
            'total_checks': total_checks,
            'passed': passed,
            'failed': failed,
            'warned': warned,
            'success_rate': f"{(passed/total_checks)*100:.1f}%" if total_checks > 0 else "0%"
        }
        
        if failed == 0:
            self.results['overall_status'] = 'PASS' if warned == 0 else 'PASS_WITH_WARNINGS'
        else:
            self.results['overall_status'] = 'FAIL'
            
    def run_all_checks(self) -> bool:
        """Run all build validation checks."""
        print("=" * 60)
        print("Metasploit Framework Build Validation")
        print("=" * 60)
        
        checks = [
            ('Python Version', self.check_python_version),
            ('Configuration Files', self.check_configuration_files),
            ('Dependencies', self.check_dependencies),
            ('Framework Structure', self.check_framework_structure),
            ('Core Imports', self.check_core_imports),
            ('Test Discovery', self.check_test_discovery),
            ('Code Linting', self.check_linting),
            ('Sample Test', self.run_sample_test)
        ]
        
        for check_name, check_func in checks:
            print(f"\nRunning {check_name}...")
            try:
                check_func()
            except Exception as e:
                self.log_result(f'check_{check_name.lower().replace(" ", "_")}', 'FAIL', 
                              f"Unexpected error in {check_name}: {e}")
                
        self.generate_summary()
        
        print("\n" + "=" * 60)
        print("BUILD VALIDATION SUMMARY")
        print("=" * 60)
        print(f"Overall Status: {self.results['overall_status']}")
        print(f"Total Checks: {self.results['summary']['total_checks']}")
        print(f"Passed: {self.results['summary']['passed']}")
        print(f"Failed: {self.results['summary']['failed']}")
        print(f"Warnings: {self.results['summary']['warned']}")
        print(f"Success Rate: {self.results['summary']['success_rate']}")
        
        if self.results['errors']:
            print(f"\nERRORS ({len(self.results['errors'])}):")
            for error in self.results['errors']:
                print(f"  - {error}")
                
        if self.results['warnings']:
            print(f"\nWARNINGS ({len(self.results['warnings'])}):")
            for warning in self.results['warnings']:
                print(f"  - {warning}")
                
        # Save detailed results
        results_file = self.root_path / 'build_validation_results.json'
        with open(results_file, 'w') as f:
            json.dump(self.results, f, indent=2)
        print(f"\nDetailed results saved to: {results_file}")
        
        return self.results['overall_status'] in ['PASS', 'PASS_WITH_WARNINGS']


def main():
    """Main entry point."""
    validator = BuildValidator()
    success = validator.run_all_checks()
    
    if success:
        print("\n✅ BUILD VALIDATION PASSED")
        sys.exit(0)
    else:
        print("\n❌ BUILD VALIDATION FAILED")
        sys.exit(1)


if __name__ == '__main__':
    main()