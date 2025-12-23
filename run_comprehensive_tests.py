#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
Enhanced Comprehensive Test Runner for Metasploit Framework.

This script runs ALL THE THINGS - an absurdly comprehensive test suite
that tests every aspect of the Metasploit Framework Python port.
"""

import os
import sys
import argparse
import subprocess
import time
import json
from pathlib import Path
from typing import List, Dict, Any, Optional
from datetime import datetime
import traceback


class ComprehensiveTestRunner:
    """Absurdly comprehensive test runner that tests ALL THE THINGS."""
    
    def __init__(self, root_dir: Optional[Path] = None):
        """Initialize the comprehensive test runner."""
        self.root_dir = root_dir or Path(__file__).parent
        self.test_dir = self.root_dir / 'test'
        self.results = {
            'total_tests': 0,
            'passed': 0,
            'failed': 0,
            'skipped': 0,
            'errors': 0,
            'duration': 0,
            'test_categories': {}
        }
        self.start_time = None
        
    def print_banner(self, message: str):
        """Print a nice banner."""
        width = 80
        print("\n" + "=" * width)
        print(f"  {message}")
        print("=" * width + "\n")
    
    def print_section(self, message: str):
        """Print a section header."""
        print(f"\n🔹 {message}")
        print("-" * 60)
    
    def run_test_suite(self, test_file: str, markers: Optional[List[str]] = None, 
                      verbose: bool = False) -> Dict[str, Any]:
        """Run a specific test suite."""
        cmd = [
            sys.executable, '-m', 'pytest',
            str(self.test_dir / test_file),
            '--tb=short',
            '--color=yes',
            '-v' if verbose else '-q',
        ]
        
        if markers:
            for marker in markers:
                cmd.extend(['-m', marker])
        
        # Add coverage if requested
        if os.environ.get('MSF_TEST_COVERAGE'):
            cmd.extend([
                '--cov=lib',
                '--cov=python_framework',
                '--cov-append',
                '--cov-report=term-missing:skip-covered'
            ])
        
        print(f"Running: {' '.join(cmd[-3:])}")
        
        try:
            start = time.time()
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=300)
            duration = time.time() - start
            
            return {
                'success': result.returncode == 0,
                'output': result.stdout,
                'errors': result.stderr,
                'duration': duration,
                'returncode': result.returncode
            }
        except subprocess.TimeoutExpired:
            return {
                'success': False,
                'output': '',
                'errors': 'Test suite timed out after 300 seconds',
                'duration': 300,
                'returncode': -1
            }
        except Exception as e:
            return {
                'success': False,
                'output': '',
                'errors': str(e),
                'duration': 0,
                'returncode': -1
            }
    
    def run_unit_tests(self, verbose: bool = False) -> Dict[str, Any]:
        """Run all unit tests."""
        self.print_section("Running Unit Tests")
        
        result = self.run_test_suite(
            'test_comprehensive_suite.py',
            markers=['unit'],
            verbose=verbose
        )
        
        if result['success']:
            print("✅ Unit tests passed")
        else:
            print("❌ Unit tests failed")
            if verbose:
                print(result['errors'])
        
        return result
    
    def run_property_based_tests(self, verbose: bool = False) -> Dict[str, Any]:
        """Run property-based tests with Hypothesis."""
        self.print_section("Running Property-Based Tests (Hypothesis)")
        
        result = self.run_test_suite(
            'test_property_based.py',
            verbose=verbose
        )
        
        if result['success']:
            print("✅ Property-based tests passed")
        else:
            print("⚠️  Property-based tests had issues (may be expected if Hypothesis not installed)")
            if verbose:
                print(result['errors'])
        
        return result
    
    def run_fuzz_tests(self, verbose: bool = False) -> Dict[str, Any]:
        """Run fuzz tests."""
        self.print_section("Running Fuzz Tests")
        
        result = self.run_test_suite(
            'test_fuzz.py',
            verbose=verbose
        )
        
        if result['success']:
            print("✅ Fuzz tests passed")
        else:
            print("❌ Fuzz tests failed")
            if verbose:
                print(result['errors'])
        
        return result
    
    def run_integration_tests(self, verbose: bool = False) -> Dict[str, Any]:
        """Run integration tests."""
        self.print_section("Running Integration Tests")
        
        result = self.run_test_suite(
            'test_integration_comprehensive.py',
            markers=['integration'],
            verbose=verbose
        )
        
        if result['success']:
            print("✅ Integration tests passed")
        else:
            print("❌ Integration tests failed")
            if verbose:
                print(result['errors'])
        
        return result
    
    def run_security_tests(self, verbose: bool = False) -> Dict[str, Any]:
        """Run security-focused tests."""
        self.print_section("Running Security Tests")
        
        results = []
        
        # Run security tests from all test files
        for test_file in ['test_comprehensive_suite.py', 'test_fuzz.py', 'test_property_based.py']:
            result = self.run_test_suite(
                test_file,
                markers=['security'],
                verbose=verbose
            )
            results.append(result)
        
        # Combine results
        all_success = all(r['success'] for r in results)
        
        if all_success:
            print("✅ Security tests passed")
        else:
            print("❌ Some security tests failed")
        
        return {
            'success': all_success,
            'output': '\n'.join(r['output'] for r in results),
            'errors': '\n'.join(r['errors'] for r in results),
            'duration': sum(r['duration'] for r in results)
        }
    
    def run_crypto_tests(self, verbose: bool = False) -> Dict[str, Any]:
        """Run cryptographic tests."""
        self.print_section("Running Cryptographic Tests")
        
        results = []
        
        # Run crypto tests from all test files
        for test_file in ['test_comprehensive_suite.py', 'test_fuzz.py', 'test_property_based.py']:
            result = self.run_test_suite(
                test_file,
                markers=['crypto'],
                verbose=verbose
            )
            results.append(result)
        
        all_success = all(r['success'] for r in results)
        
        if all_success:
            print("✅ Cryptographic tests passed")
        else:
            print("⚠️  Some cryptographic tests had issues")
        
        return {
            'success': all_success,
            'output': '\n'.join(r['output'] for r in results),
            'errors': '\n'.join(r['errors'] for r in results),
            'duration': sum(r['duration'] for r in results)
        }
    
    def run_performance_tests(self, verbose: bool = False) -> Dict[str, Any]:
        """Run performance tests."""
        self.print_section("Running Performance Tests")
        
        result = self.run_test_suite(
            'test_comprehensive_suite.py',
            markers=['performance'],
            verbose=verbose
        )
        
        if result['success']:
            print("✅ Performance tests passed")
        else:
            print("⚠️  Performance tests had issues")
        
        return result
    
    def run_network_tests(self, verbose: bool = False) -> Dict[str, Any]:
        """Run network-related tests."""
        self.print_section("Running Network Tests")
        
        results = []
        
        # Run network tests from all test files
        for test_file in ['test_comprehensive_suite.py', 'test_integration_comprehensive.py']:
            result = self.run_test_suite(
                test_file,
                markers=['network'],
                verbose=verbose
            )
            results.append(result)
        
        all_success = all(r['success'] for r in results)
        
        if all_success:
            print("✅ Network tests passed")
        else:
            print("⚠️  Some network tests had issues")
        
        return {
            'success': all_success,
            'output': '\n'.join(r['output'] for r in results),
            'errors': '\n'.join(r['errors'] for r in results),
            'duration': sum(r['duration'] for r in results)
        }
    
    def run_all_existing_tests(self, verbose: bool = False) -> Dict[str, Any]:
        """Run all existing test files."""
        self.print_section("Running All Existing Test Files")
        
        # Find all test files
        test_files = list(self.test_dir.glob('test_*.py'))
        
        print(f"Found {len(test_files)} test files")
        
        results = []
        for test_file in test_files:
            print(f"  • {test_file.name}")
            result = self.run_test_suite(test_file.name, verbose=verbose)
            results.append((test_file.name, result))
        
        all_success = all(r[1]['success'] for r in results)
        
        if all_success:
            print("✅ All existing tests passed")
        else:
            print("⚠️  Some existing tests had issues")
        
        return {
            'success': all_success,
            'output': '\n'.join(r[1]['output'] for r in results),
            'errors': '\n'.join(r[1]['errors'] for r in results),
            'duration': sum(r[1]['duration'] for r in results),
            'details': results
        }
    
    def generate_report(self):
        """Generate comprehensive test report."""
        self.print_banner("📊 TEST RESULTS SUMMARY")
        
        duration = time.time() - self.start_time if self.start_time else 0
        
        print(f"Total Duration: {duration:.2f} seconds")
        print(f"\nTest Categories Run:")
        
        for category, result in self.results['test_categories'].items():
            status = "✅ PASSED" if result.get('success') else "❌ FAILED"
            duration_str = f"{result.get('duration', 0):.2f}s"
            print(f"  {category:.<40} {status} ({duration_str})")
        
        # Calculate overall success rate
        total_categories = len(self.results['test_categories'])
        passed_categories = sum(1 for r in self.results['test_categories'].values() 
                               if r.get('success', False))
        
        print(f"\nOverall: {passed_categories}/{total_categories} test categories passed")
        
        if passed_categories == total_categories:
            print("\n🎉 ALL TESTS PASSED! 🎉")
        else:
            print(f"\n⚠️  {total_categories - passed_categories} test categories had issues")
        
        # Save report to file
        report_file = self.root_dir / 'test-results' / f'test-report-{datetime.now().strftime("%Y%m%d-%H%M%S")}.json'
        report_file.parent.mkdir(exist_ok=True)
        
        with open(report_file, 'w') as f:
            json.dump(self.results, f, indent=2)
        
        print(f"\n📄 Detailed report saved to: {report_file}")
    
    def run_comprehensive_suite(self, verbose: bool = False, 
                               categories: Optional[List[str]] = None):
        """Run the complete comprehensive test suite."""
        self.print_banner("🚀 METASPLOIT FRAMEWORK COMPREHENSIVE TEST SUITE 🚀")
        print("Testing ALL THE THINGS! 🎯\n")
        
        self.start_time = time.time()
        
        # Define test categories
        all_categories = {
            'unit': self.run_unit_tests,
            'property': self.run_property_based_tests,
            'fuzz': self.run_fuzz_tests,
            'integration': self.run_integration_tests,
            'security': self.run_security_tests,
            'crypto': self.run_crypto_tests,
            'performance': self.run_performance_tests,
            'network': self.run_network_tests,
            'existing': self.run_all_existing_tests,
        }
        
        # Filter categories if specified
        if categories:
            test_categories = {k: v for k, v in all_categories.items() if k in categories}
        else:
            test_categories = all_categories
        
        # Run all test categories
        for category, test_func in test_categories.items():
            try:
                result = test_func(verbose=verbose)
                self.results['test_categories'][category] = result
            except Exception as e:
                print(f"❌ Error running {category} tests: {e}")
                traceback.print_exc()
                self.results['test_categories'][category] = {
                    'success': False,
                    'error': str(e),
                    'duration': 0
                }
        
        # Generate final report
        self.generate_report()


def main():
    """Main entry point."""
    parser = argparse.ArgumentParser(
        description='Comprehensive Test Suite for Metasploit Framework - TEST ALL THE THINGS!'
    )
    
    parser.add_argument(
        '--verbose', '-v',
        action='store_true',
        help='Verbose output'
    )
    
    parser.add_argument(
        '--categories', '-c',
        nargs='+',
        choices=['unit', 'property', 'fuzz', 'integration', 'security', 
                'crypto', 'performance', 'network', 'existing'],
        help='Specific test categories to run (default: all)'
    )
    
    parser.add_argument(
        '--coverage',
        action='store_true',
        help='Enable code coverage reporting'
    )
    
    parser.add_argument(
        '--quick',
        action='store_true',
        help='Run only quick tests (skip slow tests)'
    )
    
    args = parser.parse_args()
    
    # Set coverage environment variable
    if args.coverage:
        os.environ['MSF_TEST_COVERAGE'] = '1'
    
    # Set quick test mode
    if args.quick:
        os.environ['MSF_TEST_QUICK'] = '1'
    
    # Run comprehensive test suite
    runner = ComprehensiveTestRunner()
    runner.run_comprehensive_suite(
        verbose=args.verbose,
        categories=args.categories
    )


if __name__ == '__main__':
    main()
