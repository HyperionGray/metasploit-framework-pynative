#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Comprehensive Test Runner for Metasploit Framework Ruby-to-Python Conversion

This script runs a comprehensive test suite to validate that the Ruby-to-Python
conversion preserved all critical functionality. It provides detailed reporting
on what works, what's broken, and what needs attention.

Usage:
    python3 test_runner_comprehensive.py [--quick] [--coverage] [--report]
"""

import sys
import os
import subprocess
import time
import json
from pathlib import Path
from datetime import datetime
import argparse


class MetasploitTestRunner:
    """Comprehensive test runner for Metasploit Framework validation"""
    
    def __init__(self, quick_mode=False, coverage_mode=False, generate_report=True):
        self.quick_mode = quick_mode
        self.coverage_mode = coverage_mode
        self.generate_report = generate_report
        self.results = {}
        self.start_time = None
        self.end_time = None
        
        # Test categories and their descriptions
        self.test_categories = {
            'framework': 'Core framework functionality tests',
            'network': 'Network and HTTP client tests', 
            'crypto': 'Cryptographic function tests',
            'binary_analysis': 'Binary analysis tool tests',
            'exploit': 'Exploit module tests',
            'payload': 'Payload generation tests',
            'integration': 'Integration and end-to-end tests',
            'security': 'Security validation tests',
            'performance': 'Performance benchmark tests'
        }
    
    def print_banner(self):
        """Print test runner banner"""
        print("=" * 80)
        print("🚀 METASPLOIT FRAMEWORK RUBY-TO-PYTHON CONVERSION TEST SUITE")
        print("=" * 80)
        print(f"📅 Started: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
        print(f"🏃 Mode: {'Quick' if self.quick_mode else 'Comprehensive'}")
        print(f"📊 Coverage: {'Enabled' if self.coverage_mode else 'Disabled'}")
        print("=" * 80)
    
    def check_prerequisites(self):
        """Check that all prerequisites are met"""
        print("\n🔍 Checking prerequisites...")
        
        # Check Python version
        python_version = sys.version_info
        print(f"  Python version: {python_version.major}.{python_version.minor}.{python_version.micro}")
        
        if python_version < (3, 8):
            print("  ❌ Python 3.8+ required")
            return False
        else:
            print("  ✅ Python version OK")
        
        # Check critical dependencies
        critical_deps = [
            'pytest', 'requests', 'cryptography', 'pyyaml'
        ]
        
        missing_deps = []
        for dep in critical_deps:
            try:
                __import__(dep)
                print(f"  ✅ {dep}")
            except ImportError:
                print(f"  ❌ {dep}")
                missing_deps.append(dep)
        
        if missing_deps:
            print(f"\n❌ Missing dependencies: {', '.join(missing_deps)}")
            print("Run: python3 tasks.py install")
            return False
        
        # Check framework structure
        critical_paths = ['lib/', 'modules/', 'tools/', 'test/', 'spec/']
        missing_paths = []
        
        for path in critical_paths:
            if Path(path).exists():
                print(f"  ✅ {path}")
            else:
                print(f"  ❌ {path}")
                missing_paths.append(path)
        
        if missing_paths:
            print(f"\n❌ Missing framework paths: {', '.join(missing_paths)}")
            return False
        
        print("✅ All prerequisites met!")
        return True
    
    def run_test_category(self, category, marker=None):
        """Run tests for a specific category"""
        print(f"\n🧪 Running {category} tests...")
        
        # Build pytest command
        cmd = ['python3', '-m', 'pytest', '-v', '--tb=short', '--color=yes']
        
        if self.coverage_mode:
            cmd.extend(['--cov=lib', '--cov=modules', '--cov=tools'])
        
        if marker:
            cmd.extend(['-m', marker])
        
        if self.quick_mode:
            cmd.extend(['-x'])  # Stop on first failure
        
        # Add test paths
        cmd.extend(['test/', 'spec/'])
        
        # Run tests
        start_time = time.time()
        result = subprocess.run(cmd, capture_output=True, text=True)
        end_time = time.time()
        
        # Parse results
        test_result = {
            'category': category,
            'marker': marker,
            'duration': end_time - start_time,
            'return_code': result.returncode,
            'stdout': result.stdout,
            'stderr': result.stderr,
            'success': result.returncode == 0
        }
        
        # Extract test counts from output
        if 'failed' in result.stdout.lower():
            test_result['status'] = 'FAILED'
            print(f"  ❌ {category} tests FAILED")
        elif 'passed' in result.stdout.lower():
            test_result['status'] = 'PASSED'
            print(f"  ✅ {category} tests PASSED")
        else:
            test_result['status'] = 'UNKNOWN'
            print(f"  ⚠️  {category} tests status UNKNOWN")
        
        print(f"  ⏱️  Duration: {test_result['duration']:.2f}s")
        
        self.results[category] = test_result
        return test_result
    
    def run_all_tests(self):
        """Run all test categories"""
        self.start_time = time.time()
        
        if self.quick_mode:
            # Quick mode: run basic tests only
            categories_to_run = [
                ('framework', 'framework'),
                ('network', 'network and unit'),
                ('crypto', 'crypto and unit')
            ]
        else:
            # Comprehensive mode: run all categories
            categories_to_run = [
                ('framework', 'framework'),
                ('network', 'network'),
                ('crypto', 'crypto'),
                ('binary_analysis', 'binary_analysis'),
                ('integration', 'integration'),
                ('security', 'security'),
                ('performance', 'performance')
            ]
        
        for category, marker in categories_to_run:
            self.run_test_category(category, marker)
            
            # In quick mode, stop on first failure
            if self.quick_mode and not self.results[category]['success']:
                print(f"\n⚠️  Quick mode: Stopping due to {category} test failure")
                break
        
        self.end_time = time.time()
    
    def generate_summary_report(self):
        """Generate a summary report of test results"""
        print("\n" + "=" * 80)
        print("📊 TEST RESULTS SUMMARY")
        print("=" * 80)
        
        total_duration = self.end_time - self.start_time if self.end_time else 0
        print(f"⏱️  Total Duration: {total_duration:.2f}s")
        
        # Count results
        passed = sum(1 for r in self.results.values() if r['success'])
        failed = sum(1 for r in self.results.values() if not r['success'])
        total = len(self.results)
        
        print(f"✅ Passed: {passed}/{total}")
        print(f"❌ Failed: {failed}/{total}")
        
        if failed == 0:
            print("\n🎉 ALL TESTS PASSED! Ruby-to-Python conversion appears successful!")
        else:
            print(f"\n⚠️  {failed} test categories failed. Review needed.")
        
        # Detailed results
        print("\n📋 Detailed Results:")
        for category, result in self.results.items():
            status_icon = "✅" if result['success'] else "❌"
            description = self.test_categories.get(category, 'Unknown category')
            print(f"  {status_icon} {category:<15} {description}")
            print(f"     Duration: {result['duration']:.2f}s")
            
            if not result['success'] and result['stderr']:
                print(f"     Error: {result['stderr'][:100]}...")
        
        return passed, failed, total


def main():
    """Main entry point"""
    parser = argparse.ArgumentParser(description='Comprehensive Metasploit Framework Test Runner')
    parser.add_argument('--quick', action='store_true', help='Run quick tests only')
    parser.add_argument('--coverage', action='store_true', help='Enable coverage reporting')
    parser.add_argument('--no-report', action='store_true', help='Skip report generation')
    
    args = parser.parse_args()
    
    # Create test runner
    runner = MetasploitTestRunner(
        quick_mode=args.quick,
        coverage_mode=args.coverage,
        generate_report=not args.no_report
    )
    
    # Run tests
    runner.print_banner()
    
    if not runner.check_prerequisites():
        print("\n❌ Prerequisites not met. Exiting.")
        sys.exit(1)
    
    runner.run_all_tests()
    passed, failed, total = runner.generate_summary_report()
    
    # Generate detailed report if requested
    if runner.generate_report:
        report_file = f"test_report_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json"
        with open(report_file, 'w') as f:
            json.dump({
                'timestamp': datetime.now().isoformat(),
                'mode': 'quick' if runner.quick_mode else 'comprehensive',
                'coverage': runner.coverage_mode,
                'summary': {
                    'passed': passed,
                    'failed': failed,
                    'total': total,
                    'duration': runner.end_time - runner.start_time
                },
                'results': runner.results
            }, f, indent=2)
        
        print(f"\n📄 Detailed report saved: {report_file}")
    
    # Exit with appropriate code
    sys.exit(0 if failed == 0 else 1)


if __name__ == '__main__':
    main()