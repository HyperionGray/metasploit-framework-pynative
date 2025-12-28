#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Metasploit Framework Test Runner

This script provides a unified interface for running different types of tests
in the Metasploit Framework Python implementation. It's designed to work with
the CI/CD pipeline and provides the same interface as the original Ruby test suite.

Usage:
    python run_tests.py [options]

Options:
    --unit              Run unit tests only
    --integration       Run integration tests
    --security          Run security-focused tests
    --performance       Run performance benchmarks
    --modules           Run module-specific tests
    --compatibility     Run Ruby compatibility tests
    --verbose           Enable verbose output
    --skip-slow         Skip slow-running tests
    --parallel          Run tests in parallel
    --coverage          Generate coverage reports
    --help              Show this help message

Examples:
    python run_tests.py --unit --verbose
    python run_tests.py --integration --coverage
    python run_tests.py --security --performance
    python run_tests.py  # Run all tests
"""

import sys
import os
import subprocess
import argparse
from pathlib import Path
import shutil


class TestRunner:
    """Unified test runner for Metasploit Framework"""
    
    def __init__(self):
        self.project_root = Path(__file__).parent
        self.test_results_dir = self.project_root / "test-results"
        self.coverage_dir = self.project_root / "htmlcov"
        
        # Ensure output directories exist
        self.test_results_dir.mkdir(exist_ok=True)
        self.coverage_dir.mkdir(exist_ok=True)
    
    def run_command(self, cmd, description="Running command"):
        """Execute a command and return the result"""
        print(f"🔧 {description}")
        print(f"   Command: {' '.join(cmd)}")
        
        try:
            result = subprocess.run(cmd, cwd=self.project_root, check=False)
            if result.returncode == 0:
                print(f"✅ {description} - SUCCESS")
            else:
                print(f"❌ {description} - FAILED (exit code: {result.returncode})")
            return result.returncode
        except Exception as e:
            print(f"❌ {description} - ERROR: {e}")
            return 1
    
    def run_unit_tests(self, verbose=False, skip_slow=False, coverage=False):
        """Run unit tests"""
        cmd = ["python", "-m", "pytest"]
        
        # Test paths
        cmd.extend(["test/", "spec/"])
        
        # Test markers - exclude integration, functional, security, performance
        markers = "not integration and not functional and not security and not performance and not slow"
        if not skip_slow:
            markers = "not integration and not functional and not security and not performance"
        
        cmd.extend(["-m", markers])
        
        # Output configuration
        cmd.extend([
            "--junitxml=test-results/unit-results.xml",
            "--tb=short"
        ])
        
        if verbose:
            cmd.append("--verbose")
        else:
            cmd.append("-q")
        
        if coverage:
            cmd.extend([
                "--cov=lib",
                "--cov=modules", 
                "--cov-report=html:htmlcov/unit",
                "--cov-report=xml:coverage-unit.xml"
            ])
        
        return self.run_command(cmd, "Unit Tests")
    
    def run_integration_tests(self, verbose=False, coverage=False):
        """Run integration tests"""
        cmd = ["python", "-m", "pytest"]
        
        # Test paths
        cmd.extend(["test/", "spec/"])
        
        # Test markers - only integration tests
        cmd.extend(["-m", "integration"])
        
        # Output configuration
        cmd.extend([
            "--junitxml=test-results/integration-results.xml",
            "--tb=short"
        ])
        
        if verbose:
            cmd.append("--verbose")
        else:
            cmd.append("-q")
        
        if coverage:
            cmd.extend([
                "--cov=lib",
                "--cov=modules",
                "--cov-report=html:htmlcov/integration", 
                "--cov-report=xml:coverage-integration.xml"
            ])
        
        return self.run_command(cmd, "Integration Tests")
    
    def run_security_tests(self, verbose=False, coverage=False):
        """Run security-focused tests"""
        cmd = ["python", "-m", "pytest"]
        
        # Test paths
        cmd.extend(["test/", "spec/"])
        
        # Test markers - only security tests
        cmd.extend(["-m", "security"])
        
        # Output configuration
        cmd.extend([
            "--junitxml=test-results/security-results.xml",
            "--tb=short"
        ])
        
        if verbose:
            cmd.append("--verbose")
        else:
            cmd.append("-q")
        
        if coverage:
            cmd.extend([
                "--cov=lib",
                "--cov=modules",
                "--cov-report=html:htmlcov/security",
                "--cov-report=xml:coverage-security.xml"
            ])
        
        return self.run_command(cmd, "Security Tests")
    
    def run_performance_tests(self, verbose=False):
        """Run performance benchmarks"""
        cmd = ["python", "-m", "pytest"]
        
        # Test paths
        cmd.extend(["test/", "spec/"])
        
        # Test markers - only performance tests
        cmd.extend(["-m", "performance"])
        
        # Output configuration
        cmd.extend([
            "--junitxml=test-results/performance-results.xml",
            "--benchmark-json=test-results/benchmark-results.json",
            "--tb=short"
        ])
        
        if verbose:
            cmd.append("--verbose")
        else:
            cmd.append("-q")
        
        return self.run_command(cmd, "Performance Tests")
    
    def run_module_tests(self, verbose=False, coverage=False):
        """Run module-specific tests"""
        cmd = ["python", "-m", "pytest"]
        
        # Test paths - focus on module tests
        cmd.extend(["test/", "spec/"])
        
        # Test markers - module-related tests
        cmd.extend(["-m", "exploit or auxiliary or payload or encoder"])
        
        # Output configuration
        cmd.extend([
            "--junitxml=test-results/module-results.xml",
            "--tb=short"
        ])
        
        if verbose:
            cmd.append("--verbose")
        else:
            cmd.append("-q")
        
        if coverage:
            cmd.extend([
                "--cov=modules",
                "--cov-report=html:htmlcov/modules",
                "--cov-report=xml:coverage-modules.xml"
            ])
        
        return self.run_command(cmd, "Module Tests")
    
    def run_compatibility_tests(self, verbose=False):
        """Run Ruby compatibility tests"""
        cmd = ["python", "-m", "pytest"]
        
        # Test paths
        cmd.extend(["test/", "spec/"])
        
        # Test markers - Ruby compatibility tests
        cmd.extend(["-m", "ruby_compat"])
        
        # Output configuration
        cmd.extend([
            "--junitxml=test-results/compatibility-results.xml",
            "--tb=short"
        ])
        
        if verbose:
            cmd.append("--verbose")
        else:
            cmd.append("-q")
        
        return self.run_command(cmd, "Ruby Compatibility Tests")
    
    def run_all_tests(self, verbose=False, parallel=False, coverage=True):
        """Run all tests with comprehensive coverage"""
        cmd = ["python", "-m", "pytest"]
        
        # Test paths
        cmd.extend(["test/", "spec/"])
        
        # Output configuration
        cmd.extend([
            "--junitxml=test-results/junit.xml",
            "--tb=short"
        ])
        
        if verbose:
            cmd.append("--verbose")
        else:
            cmd.append("-q")
        
        if parallel:
            # Use pytest-xdist for parallel execution
            cmd.extend(["-n", "auto"])
        
        if coverage:
            cmd.extend([
                "--cov=lib",
                "--cov=modules",
                "--cov=tools",
                "--cov-report=html:htmlcov",
                "--cov-report=xml:coverage.xml",
                "--cov-report=term-missing",
                "--cov-branch"
            ])
        
        return self.run_command(cmd, "All Tests")
    
    def check_dependencies(self):
        """Check if required dependencies are installed"""
        print("🔍 Checking dependencies...")
        
        required_packages = ["pytest", "coverage", "pytest-cov"]
        missing_packages = []
        
        for package in required_packages:
            try:
                __import__(package.replace("-", "_"))
                print(f"   ✅ {package}")
            except ImportError:
                print(f"   ❌ {package} - MISSING")
                missing_packages.append(package)
        
        if missing_packages:
            print(f"\n❌ Missing packages: {', '.join(missing_packages)}")
            print("   Install with: pip install -r requirements.txt")
            return False
        
        print("✅ All dependencies available")
        return True


def main():
    """Main entry point"""
    parser = argparse.ArgumentParser(
        description="Metasploit Framework Test Runner",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=__doc__
    )
    
    # Test type options
    parser.add_argument("--unit", action="store_true", help="Run unit tests only")
    parser.add_argument("--integration", action="store_true", help="Run integration tests")
    parser.add_argument("--security", action="store_true", help="Run security-focused tests")
    parser.add_argument("--performance", action="store_true", help="Run performance benchmarks")
    parser.add_argument("--modules", action="store_true", help="Run module-specific tests")
    parser.add_argument("--compatibility", action="store_true", help="Run Ruby compatibility tests")
    
    # Execution options
    parser.add_argument("--verbose", action="store_true", help="Enable verbose output")
    parser.add_argument("--skip-slow", action="store_true", help="Skip slow-running tests")
    parser.add_argument("--parallel", action="store_true", help="Run tests in parallel")
    parser.add_argument("--coverage", action="store_true", help="Generate coverage reports")
    
    args = parser.parse_args()
    
    # Create test runner
    runner = TestRunner()
    
    # Check dependencies
    if not runner.check_dependencies():
        return 1
    
    # Determine what tests to run
    test_types = []
    if args.unit:
        test_types.append("unit")
    if args.integration:
        test_types.append("integration")
    if args.security:
        test_types.append("security")
    if args.performance:
        test_types.append("performance")
    if args.modules:
        test_types.append("modules")
    if args.compatibility:
        test_types.append("compatibility")
    
    # If no specific tests requested, run all
    if not test_types:
        test_types = ["all"]
    
    print(f"🚀 Starting Metasploit Framework Tests")
    print(f"   Test types: {', '.join(test_types)}")
    print(f"   Verbose: {args.verbose}")
    print(f"   Coverage: {args.coverage}")
    print(f"   Parallel: {args.parallel}")
    print()
    
    # Run tests
    exit_code = 0
    
    for test_type in test_types:
        if test_type == "unit":
            result = runner.run_unit_tests(args.verbose, args.skip_slow, args.coverage)
        elif test_type == "integration":
            result = runner.run_integration_tests(args.verbose, args.coverage)
        elif test_type == "security":
            result = runner.run_security_tests(args.verbose, args.coverage)
        elif test_type == "performance":
            result = runner.run_performance_tests(args.verbose)
        elif test_type == "modules":
            result = runner.run_module_tests(args.verbose, args.coverage)
        elif test_type == "compatibility":
            result = runner.run_compatibility_tests(args.verbose)
        elif test_type == "all":
            result = runner.run_all_tests(args.verbose, args.parallel, args.coverage)
        else:
            print(f"❌ Unknown test type: {test_type}")
            result = 1
        
        if result != 0:
            exit_code = result
        
        print()  # Add spacing between test runs
    
    # Final summary
    if exit_code == 0:
        print("🎉 All tests completed successfully!")
    else:
        print(f"❌ Tests failed with exit code: {exit_code}")
    
    return exit_code


if __name__ == "__main__":
    sys.exit(main())