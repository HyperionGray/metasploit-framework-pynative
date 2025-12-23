#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
Comprehensive Test Runner for Metasploit Framework.

This script provides a comprehensive test runner that can execute different
types of tests with proper organization, reporting, and CI/CD integration.
"""

import os
import sys
import argparse
import subprocess
import time
from pathlib import Path
from typing import List, Dict, Any, Optional
import json

# Add lib path
sys.path.insert(0, os.path.join(os.path.dirname(__file__), 'lib'))


class MSFTestRunner:
    """Comprehensive test runner for MSF framework."""
    
    def __init__(self, root_dir: Optional[Path] = None):
        """Initialize test runner."""
        self.root_dir = root_dir or Path(__file__).parent
        self.test_dir = self.root_dir / 'test'
        self.spec_dir = self.root_dir / 'spec'
        self.results = {}
        
    def run_unit_tests(self, verbose: bool = False) -> Dict[str, Any]:
        """Run unit tests."""
        print("🧪 Running Unit Tests...")
        
        cmd = [
            'python', '-m', 'pytest',
            '-m', 'unit',
            '--tb=short',
            '--cov=lib',
            '--cov-report=term-missing',
            '--cov-report=html:htmlcov/unit',
            '--junit-xml=test-results/unit-results.xml'
        ]
        
        if verbose:
            cmd.extend(['-v', '-s'])
            
        result = self._run_command(cmd)
        self.results['unit_tests'] = result
        return result
        
    def run_integration_tests(self, verbose: bool = False) -> Dict[str, Any]:
        """Run integration tests."""
        print("🔗 Running Integration Tests...")
        
        cmd = [
            'python', '-m', 'pytest',
            '-m', 'integration',
            '--tb=short',
            '--junit-xml=test-results/integration-results.xml'
        ]
        
        if verbose:
            cmd.extend(['-v', '-s'])
            
        result = self._run_command(cmd)
        self.results['integration_tests'] = result
        return result
        
    def run_security_tests(self, verbose: bool = False) -> Dict[str, Any]:
        """Run security-focused tests."""
        print("🔒 Running Security Tests...")
        
        cmd = [
            'python', '-m', 'pytest',
            '-m', 'security',
            '--tb=short',
            '--junit-xml=test-results/security-results.xml'
        ]
        
        if verbose:
            cmd.extend(['-v', '-s'])
            
        result = self._run_command(cmd)
        self.results['security_tests'] = result
        return result
        
    def run_performance_tests(self, verbose: bool = False) -> Dict[str, Any]:
        """Run performance tests."""
        print("⚡ Running Performance Tests...")
        
        cmd = [
            'python', '-m', 'pytest',
            '-m', 'performance',
            '--tb=short',
            '--benchmark-only',
            '--benchmark-json=test-results/benchmark-results.json',
            '--junit-xml=test-results/performance-results.xml'
        ]
        
        if verbose:
            cmd.extend(['-v', '-s'])
            
        result = self._run_command(cmd)
        self.results['performance_tests'] = result
        return result
        
    def run_http_tests(self, verbose: bool = False) -> Dict[str, Any]:
        """Run HTTP client tests."""
        print("🌐 Running HTTP Client Tests...")
        
        cmd = [
            'python', '-m', 'pytest',
            '-m', 'http',
            '--tb=short',
            '--junit-xml=test-results/http-results.xml'
        ]
        
        if verbose:
            cmd.extend(['-v', '-s'])
            
        result = self._run_command(cmd)
        self.results['http_tests'] = result
        return result
        
    def run_crypto_tests(self, verbose: bool = False) -> Dict[str, Any]:
        """Run cryptographic tests."""
        print("🔐 Running Cryptographic Tests...")
        
        cmd = [
            'python', '-m', 'pytest',
            '-m', 'crypto',
            '--tb=short',
            '--junit-xml=test-results/crypto-results.xml'
        ]
        
        if verbose:
            cmd.extend(['-v', '-s'])
            
        result = self._run_command(cmd)
        self.results['crypto_tests'] = result
        return result
        
    def run_module_tests(self, verbose: bool = False) -> Dict[str, Any]:
        """Run module loading and validation tests."""
        print("📦 Running Module Tests...")
        
        cmd = [
            'python', '-m', 'pytest',
            'test/test_module_loading_comprehensive.py',
            '--tb=short',
            '--junit-xml=test-results/module-results.xml'
        ]
        
        if verbose:
            cmd.extend(['-v', '-s'])
            
        result = self._run_command(cmd)
        self.results['module_tests'] = result
        return result
        
    def run_compatibility_tests(self, verbose: bool = False) -> Dict[str, Any]:
        """Run Ruby compatibility tests."""
        print("🔄 Running Ruby Compatibility Tests...")
        
        cmd = [
            'python', '-m', 'pytest',
            '-m', 'ruby_compat',
            '--tb=short',
            '--junit-xml=test-results/compatibility-results.xml'
        ]
        
        if verbose:
            cmd.extend(['-v', '-s'])
            
        result = self._run_command(cmd)
        self.results['compatibility_tests'] = result
        return result
        
    def run_all_tests(self, verbose: bool = False, skip_slow: bool = False) -> Dict[str, Any]:
        """Run all test suites."""
        print("🚀 Running All Tests...")
        
        cmd = [
            'python', '-m', 'pytest',
            '--tb=short',
            '--cov=lib',
            '--cov=modules',
            '--cov-report=term-missing',
            '--cov-report=html:htmlcov/all',
            '--cov-report=xml',
            '--junit-xml=test-results/all-results.xml'
        ]
        
        if skip_slow:
            cmd.extend(['-m', 'not slow'])
            
        if verbose:
            cmd.extend(['-v', '-s'])
            
        result = self._run_command(cmd)
        self.results['all_tests'] = result
        return result
        
    def run_code_quality_checks(self) -> Dict[str, Any]:
        """Run code quality checks."""
        print("✨ Running Code Quality Checks...")
        
        results = {}
        
        # Flake8
        print("  Running flake8...")
        flake8_result = self._run_command(['flake8', 'lib/', 'test/', '--max-line-length=120'])
        results['flake8'] = flake8_result
        
        # Black
        print("  Running black...")
        black_result = self._run_command(['black', '--check', '--diff', 'lib/', 'test/'])
        results['black'] = black_result
        
        # isort
        print("  Running isort...")
        isort_result = self._run_command(['isort', '--check-only', '--diff', 'lib/', 'test/'])
        results['isort'] = isort_result
        
        # Bandit (security)
        print("  Running bandit...")
        bandit_result = self._run_command(['bandit', '-r', 'lib/', '-f', 'json', '-o', 'test-results/bandit-results.json'])
        results['bandit'] = bandit_result
        
        # Safety (dependency security)
        print("  Running safety...")
        safety_result = self._run_command(['safety', 'check', '--json', '--output', 'test-results/safety-results.json'])
        results['safety'] = safety_result
        
        self.results['code_quality'] = results
        return results
        
    def generate_coverage_report(self) -> Dict[str, Any]:
        """Generate comprehensive coverage report."""
        print("📊 Generating Coverage Report...")
        
        cmd = [
            'python', '-m', 'coverage', 'report',
            '--show-missing',
            '--skip-covered'
        ]
        
        result = self._run_command(cmd)
        
        # Generate HTML report
        html_cmd = ['python', '-m', 'coverage', 'html', '-d', 'htmlcov/coverage']
        self._run_command(html_cmd)
        
        return result
        
    def _run_command(self, cmd: List[str]) -> Dict[str, Any]:
        """Run a command and return results."""
        start_time = time.time()
        
        try:
            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                cwd=self.root_dir
            )
            
            end_time = time.time()
            duration = end_time - start_time
            
            return {
                'command': ' '.join(cmd),
                'returncode': result.returncode,
                'stdout': result.stdout,
                'stderr': result.stderr,
                'duration': duration,
                'success': result.returncode == 0
            }
            
        except Exception as e:
            end_time = time.time()
            duration = end_time - start_time
            
            return {
                'command': ' '.join(cmd),
                'returncode': -1,
                'stdout': '',
                'stderr': str(e),
                'duration': duration,
                'success': False
            }
            
    def setup_test_environment(self):
        """Set up test environment."""
        print("🔧 Setting up test environment...")
        
        # Create test results directory
        results_dir = self.root_dir / 'test-results'
        results_dir.mkdir(exist_ok=True)
        
        # Create coverage directory
        coverage_dir = self.root_dir / 'htmlcov'
        coverage_dir.mkdir(exist_ok=True)
        
        # Install test dependencies
        print("  Installing test dependencies...")
        pip_result = self._run_command([
            'pip', 'install', '-r', 'requirements.txt'
        ])
        
        if not pip_result['success']:
            print(f"⚠️  Warning: Failed to install dependencies: {pip_result['stderr']}")
            
    def print_summary(self):
        """Print test results summary."""
        print("\n" + "="*80)
        print("📋 TEST RESULTS SUMMARY")
        print("="*80)
        
        total_tests = 0
        passed_tests = 0
        
        for test_type, result in self.results.items():
            if isinstance(result, dict) and 'success' in result:
                status = "✅ PASS" if result['success'] else "❌ FAIL"
                duration = f"{result['duration']:.2f}s"
                print(f"{test_type:20} {status:10} ({duration})")
                
                if result['success']:
                    passed_tests += 1
                total_tests += 1
                
        print("-" * 80)
        print(f"Total: {passed_tests}/{total_tests} test suites passed")
        
        if passed_tests == total_tests:
            print("🎉 All tests passed!")
        else:
            print("⚠️  Some tests failed. Check the output above for details.")
            
    def save_results(self, output_file: str = 'test-results/summary.json'):
        """Save test results to JSON file."""
        output_path = self.root_dir / output_file
        output_path.parent.mkdir(exist_ok=True)
        
        with open(output_path, 'w') as f:
            json.dump(self.results, f, indent=2, default=str)
            
        print(f"📄 Results saved to {output_path}")


def main():
    """Main entry point."""
    parser = argparse.ArgumentParser(description='MSF Framework Test Runner')
    parser.add_argument('--verbose', '-v', action='store_true', help='Verbose output')
    parser.add_argument('--skip-slow', action='store_true', help='Skip slow tests')
    parser.add_argument('--unit', action='store_true', help='Run unit tests only')
    parser.add_argument('--integration', action='store_true', help='Run integration tests only')
    parser.add_argument('--security', action='store_true', help='Run security tests only')
    parser.add_argument('--performance', action='store_true', help='Run performance tests only')
    parser.add_argument('--http', action='store_true', help='Run HTTP tests only')
    parser.add_argument('--crypto', action='store_true', help='Run crypto tests only')
    parser.add_argument('--modules', action='store_true', help='Run module tests only')
    parser.add_argument('--compatibility', action='store_true', help='Run compatibility tests only')
    parser.add_argument('--quality', action='store_true', help='Run code quality checks only')
    parser.add_argument('--coverage', action='store_true', help='Generate coverage report only')
    parser.add_argument('--setup', action='store_true', help='Set up test environment only')
    
    args = parser.parse_args()
    
    runner = MSFTestRunner()
    
    # Set up environment if requested
    if args.setup:
        runner.setup_test_environment()
        return
        
    # Run specific test suites
    if args.unit:
        runner.run_unit_tests(verbose=args.verbose)
    elif args.integration:
        runner.run_integration_tests(verbose=args.verbose)
    elif args.security:
        runner.run_security_tests(verbose=args.verbose)
    elif args.performance:
        runner.run_performance_tests(verbose=args.verbose)
    elif args.http:
        runner.run_http_tests(verbose=args.verbose)
    elif args.crypto:
        runner.run_crypto_tests(verbose=args.verbose)
    elif args.modules:
        runner.run_module_tests(verbose=args.verbose)
    elif args.compatibility:
        runner.run_compatibility_tests(verbose=args.verbose)
    elif args.quality:
        runner.run_code_quality_checks()
    elif args.coverage:
        runner.generate_coverage_report()
    else:
        # Run all tests by default
        runner.setup_test_environment()
        runner.run_all_tests(verbose=args.verbose, skip_slow=args.skip_slow)
        runner.run_code_quality_checks()
        runner.generate_coverage_report()
        
    # Print summary and save results
    runner.print_summary()
    runner.save_results()


if __name__ == '__main__':
    main()