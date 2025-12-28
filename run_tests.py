#!/usr/bin/env python3
"""
Metasploit Framework Python Test Runner

This script provides a unified interface for running different categories of tests
in the Metasploit Framework Python implementation. It acts as a facade over pytest
with specific test categorization and execution modes expected by the CI system.

Usage:
    python run_tests.py [options]

Test Categories:
    --unit          Run unit tests only
    --integration   Run integration tests only  
    --security      Run security-focused tests only
    --performance   Run performance/benchmark tests only
    --modules       Run module-specific tests only
    --compatibility Run Ruby compatibility tests only
    --all           Run all test categories (default)

Options:
    --verbose       Enable verbose output
    --skip-slow     Skip slow-running tests
    --coverage      Generate coverage reports
    --parallel      Run tests in parallel
    --help          Show this help message

Examples:
    python run_tests.py --unit --verbose
    python run_tests.py --integration --coverage
    python run_tests.py --all --skip-slow
"""

import argparse
import os
import sys
import subprocess
from pathlib import Path


class TestRunner:
    """Unified test runner for Metasploit Framework Python tests."""
    
    def __init__(self):
        self.base_dir = Path(__file__).parent
        self.test_results_dir = self.base_dir / "test-results"
        self.coverage_dir = self.base_dir / "htmlcov"
        
        # Ensure results directories exist
        self.test_results_dir.mkdir(exist_ok=True)
        self.coverage_dir.mkdir(exist_ok=True)
    
    def build_pytest_command(self, args):
        """Build pytest command based on provided arguments."""
        cmd = ["python", "-m", "pytest"]
        
        # Base pytest options
        cmd.extend([
            "--strict-markers",
            "--strict-config",
            "--tb=short",
            "--color=yes"
        ])
        
        # Verbose output
        if args.verbose:
            cmd.append("-v")
        else:
            cmd.append("-q")
        
        # Coverage options
        if args.coverage:
            cmd.extend([
                "--cov=lib",
                "--cov=modules", 
                "--cov=tools",
                "--cov-report=term-missing",
                "--cov-report=html:htmlcov",
                "--cov-report=xml:coverage.xml",
                "--cov-branch"
            ])
        
        # Parallel execution
        if args.parallel:
            try:
                import pytest_xdist
                cmd.extend(["-n", "auto"])
            except ImportError:
                print("Warning: pytest-xdist not installed, running tests sequentially")
        
        # Skip slow tests
        if args.skip_slow:
            cmd.extend(["-m", "not slow"])
        
        # Test category selection
        markers = []
        if args.unit:
            markers.append("unit")
        if args.integration:
            markers.append("integration")
        if args.security:
            markers.append("security")
        if args.performance:
            markers.append("performance")
        if args.modules:
            markers.extend(["exploit", "auxiliary", "payload", "encoder"])
        if args.compatibility:
            markers.append("ruby_compat")
        
        # If specific categories selected, add marker filter
        if markers:
            marker_expr = " or ".join(markers)
            cmd.extend(["-m", marker_expr])
        
        # Output files based on test category
        if args.unit:
            cmd.extend([
                "--junit-xml=test-results/unit-results.xml",
                "--html=test-results/unit-report.html"
            ])
        elif args.integration:
            cmd.extend([
                "--junit-xml=test-results/integration-results.xml",
                "--html=test-results/integration-report.html"
            ])
        elif args.security:
            cmd.extend([
                "--junit-xml=test-results/security-results.xml",
                "--html=test-results/security-report.html"
            ])
        elif args.performance:
            cmd.extend([
                "--junit-xml=test-results/benchmark-results.xml",
                "--html=test-results/benchmark-report.html",
                "--benchmark-json=test-results/benchmark-results.json"
            ])
        elif args.modules:
            cmd.extend([
                "--junit-xml=test-results/module-results.xml",
                "--html=test-results/module-report.html"
            ])
        elif args.compatibility:
            cmd.extend([
                "--junit-xml=test-results/compatibility-results.xml",
                "--html=test-results/compatibility-report.html"
            ])
        else:
            # All tests
            cmd.extend([
                "--junit-xml=test-results/all-results.xml",
                "--html=test-results/all-report.html"
            ])
        
        return cmd
    
    def run_tests(self, args):
        """Execute the test suite with specified options."""
        print(f"🧪 Running Metasploit Framework Python Tests")
        print(f"📁 Working directory: {self.base_dir}")
        print(f"📊 Results directory: {self.test_results_dir}")
        
        # Build and execute pytest command
        cmd = self.build_pytest_command(args)
        
        print(f"🚀 Executing: {' '.join(cmd)}")
        print("-" * 80)
        
        try:
            result = subprocess.run(cmd, cwd=self.base_dir, check=False)
            return result.returncode
        except KeyboardInterrupt:
            print("\n⚠️  Test execution interrupted by user")
            return 130
        except Exception as e:
            print(f"❌ Error executing tests: {e}")
            return 1
    
    def check_dependencies(self):
        """Check if required test dependencies are installed."""
        required_packages = [
            "pytest",
            "pytest-cov", 
            "pytest-html",
            "pytest-mock"
        ]
        
        missing_packages = []
        for package in required_packages:
            try:
                __import__(package.replace("-", "_"))
            except ImportError:
                missing_packages.append(package)
        
        if missing_packages:
            print(f"❌ Missing required test packages: {', '.join(missing_packages)}")
            print(f"💡 Install with: pip install {' '.join(missing_packages)}")
            return False
        
        return True


def main():
    """Main entry point for the test runner."""
    parser = argparse.ArgumentParser(
        description="Metasploit Framework Python Test Runner",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=__doc__
    )
    
    # Test category options
    test_group = parser.add_argument_group("Test Categories")
    test_group.add_argument("--unit", action="store_true", 
                           help="Run unit tests only")
    test_group.add_argument("--integration", action="store_true",
                           help="Run integration tests only")
    test_group.add_argument("--security", action="store_true",
                           help="Run security-focused tests only")
    test_group.add_argument("--performance", action="store_true",
                           help="Run performance/benchmark tests only")
    test_group.add_argument("--modules", action="store_true",
                           help="Run module-specific tests only")
    test_group.add_argument("--compatibility", action="store_true",
                           help="Run Ruby compatibility tests only")
    test_group.add_argument("--all", action="store_true",
                           help="Run all test categories (default)")
    
    # Execution options
    exec_group = parser.add_argument_group("Execution Options")
    exec_group.add_argument("--verbose", action="store_true",
                           help="Enable verbose output")
    exec_group.add_argument("--skip-slow", action="store_true",
                           help="Skip slow-running tests")
    exec_group.add_argument("--coverage", action="store_true",
                           help="Generate coverage reports")
    exec_group.add_argument("--parallel", action="store_true",
                           help="Run tests in parallel")
    
    args = parser.parse_args()
    
    # If no specific category is selected, default to all
    if not any([args.unit, args.integration, args.security, 
                args.performance, args.modules, args.compatibility]):
        args.all = True
    
    # Initialize test runner
    runner = TestRunner()
    
    # Check dependencies
    if not runner.check_dependencies():
        return 1
    
    # Run tests
    return runner.run_tests(args)


if __name__ == "__main__":
    sys.exit(main())