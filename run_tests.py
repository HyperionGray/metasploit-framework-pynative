#!/usr/bin/env python3
"""
Comprehensive Test Runner for Metasploit Framework

This script provides a unified interface for running different types of tests:
- Unit tests
- Integration tests  
- End-to-end tests with Playwright
- Performance tests
- Security tests

Usage:
    python run_tests.py --help
    python run_tests.py unit
    python run_tests.py integration
    python run_tests.py e2e
    python run_tests.py all
"""

import argparse
import os
import sys
import subprocess
import time
from pathlib import Path
from typing import List, Dict, Optional

# Test configuration
TEST_CONFIG = {
    "unit": {
        "command": ["pytest", "-m", "unit", "--cov=lib", "--cov=modules", "--cov-report=html", "--cov-report=xml"],
        "description": "Run unit tests with coverage",
        "timeout": 300,
    },
    "integration": {
        "command": ["pytest", "-m", "integration", "--cov=lib", "--cov=modules"],
        "description": "Run integration tests",
        "timeout": 600,
    },
    "e2e": {
        "command": ["pytest", "-m", "e2e", "--browser=chromium", "--headed=false"],
        "description": "Run end-to-end tests with Playwright",
        "timeout": 1200,
    },
    "security": {
        "command": ["pytest", "-m", "security", "--tb=short"],
        "description": "Run security-focused tests",
        "timeout": 900,
    },
    "performance": {
        "command": ["pytest", "-m", "performance", "--benchmark-only"],
        "description": "Run performance and benchmark tests",
        "timeout": 600,
    },
    "all": {
        "command": ["pytest", "--cov=lib", "--cov=modules", "--cov-report=html", "--cov-report=xml"],
        "description": "Run all tests with full coverage",
        "timeout": 1800,
    }
}

def setup_environment():
    """Set up test environment and directories."""
    # Create test result directories
    os.makedirs("test-results", exist_ok=True)
    os.makedirs("test-results/videos", exist_ok=True)
    os.makedirs("test-results/screenshots", exist_ok=True)
    os.makedirs("test-results/traces", exist_ok=True)
    os.makedirs("htmlcov", exist_ok=True)
    
    # Set environment variables
    os.environ.setdefault("PYTHONPATH", str(Path.cwd()))
    os.environ.setdefault("TEST_BASE_URL", "http://localhost:3000")
    os.environ.setdefault("TEST_HEADLESS", "true")

def install_dependencies():
    """Install test dependencies if needed."""
    print("🔧 Installing test dependencies...")
    
    try:
        # Install Python dependencies
        subprocess.run([sys.executable, "-m", "pip", "install", "-r", "requirements.txt"], 
                      check=True, capture_output=True)
        
        # Install Playwright browsers
        subprocess.run([sys.executable, "-m", "playwright", "install"], 
                      check=True, capture_output=True)
        
        print("✅ Dependencies installed successfully")
    except subprocess.CalledProcessError as e:
        print(f"❌ Failed to install dependencies: {e}")
        return False
    
    return True

def run_test_suite(test_type: str, verbose: bool = False, parallel: bool = False) -> bool:
    """Run a specific test suite."""
    if test_type not in TEST_CONFIG:
        print(f"❌ Unknown test type: {test_type}")
        return False
    
    config = TEST_CONFIG[test_type]
    command = config["command"].copy()
    
    # Add verbose flag if requested
    if verbose:
        command.append("-v")
    
    # Add parallel execution if requested
    if parallel and test_type != "e2e":  # E2E tests handle parallelism differently
        command.extend(["-n", "auto"])
    
    print(f"🧪 Running {test_type} tests: {config['description']}")
    print(f"📝 Command: {' '.join(command)}")
    
    start_time = time.time()
    
    try:
        result = subprocess.run(
            command,
            timeout=config["timeout"],
            capture_output=not verbose,
            text=True
        )
        
        end_time = time.time()
        duration = end_time - start_time
        
        if result.returncode == 0:
            print(f"✅ {test_type} tests passed in {duration:.2f}s")
            return True
        else:
            print(f"❌ {test_type} tests failed in {duration:.2f}s")
            if not verbose and result.stdout:
                print("STDOUT:", result.stdout[-1000:])  # Last 1000 chars
            if not verbose and result.stderr:
                print("STDERR:", result.stderr[-1000:])  # Last 1000 chars
            return False
            
    except subprocess.TimeoutExpired:
        print(f"⏰ {test_type} tests timed out after {config['timeout']}s")
        return False
    except Exception as e:
        print(f"💥 Error running {test_type} tests: {e}")
        return False

def generate_report(results: Dict[str, bool]):
    """Generate a test report."""
    print("\n" + "="*60)
    print("📊 TEST RESULTS SUMMARY")
    print("="*60)
    
    total_tests = len(results)
    passed_tests = sum(1 for result in results.values() if result)
    failed_tests = total_tests - passed_tests
    
    for test_type, passed in results.items():
        status = "✅ PASSED" if passed else "❌ FAILED"
        print(f"{test_type.upper():12} {status}")
    
    print("-"*60)
    print(f"TOTAL:       {passed_tests}/{total_tests} passed")
    
    if failed_tests > 0:
        print(f"\n⚠️  {failed_tests} test suite(s) failed")
        return False
    else:
        print("\n🎉 All test suites passed!")
        return True

def main():
    """Main entry point."""
    parser = argparse.ArgumentParser(
        description="Comprehensive test runner for Metasploit Framework",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python run_tests.py unit                    # Run unit tests only
  python run_tests.py integration --verbose   # Run integration tests with verbose output
  python run_tests.py e2e --parallel          # Run E2E tests in parallel
  python run_tests.py all                     # Run all test suites
  python run_tests.py unit integration        # Run multiple specific test suites
        """
    )
    
    parser.add_argument(
        "test_types",
        nargs="+",
        choices=list(TEST_CONFIG.keys()),
        help="Type(s) of tests to run"
    )
    
    parser.add_argument(
        "--verbose", "-v",
        action="store_true",
        help="Enable verbose output"
    )
    
    parser.add_argument(
        "--parallel", "-p",
        action="store_true",
        help="Run tests in parallel where possible"
    )
    
    parser.add_argument(
        "--install-deps",
        action="store_true",
        help="Install dependencies before running tests"
    )
    
    parser.add_argument(
        "--no-setup",
        action="store_true",
        help="Skip environment setup"
    )
    
    args = parser.parse_args()
    
    # Setup environment
    if not args.no_setup:
        setup_environment()
    
    # Install dependencies if requested
    if args.install_deps:
        if not install_dependencies():
            sys.exit(1)
    
    # Run tests
    results = {}
    
    for test_type in args.test_types:
        if test_type == "all":
            # Run all test types except "all" itself
            for t in TEST_CONFIG.keys():
                if t != "all":
                    results[t] = run_test_suite(t, args.verbose, args.parallel)
        else:
            results[test_type] = run_test_suite(test_type, args.verbose, args.parallel)
    
    # Generate report
    success = generate_report(results)
    
    # Exit with appropriate code
    sys.exit(0 if success else 1)

if __name__ == "__main__":
    main()