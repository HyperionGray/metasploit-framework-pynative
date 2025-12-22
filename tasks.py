#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Task management for Metasploit Framework (converted from Rakefile)

Run tasks with: python3 tasks.py <task_name>

Available test categories:
- test: Run all tests
- test-unit: Run unit tests only
- test-integration: Run integration tests
- test-functional: Run functional tests
- test-security: Run security-focused tests
- test-performance: Run performance benchmarks
- test-coverage: Run tests with coverage reporting
- test-parallel: Run tests in parallel
"""

import sys
import subprocess
import os
from pathlib import Path


def task_test():
    """Run all tests"""
    print("🧪 Running all tests...")
    cmd = [
        "python3", "-m", "pytest", 
        "test/", "spec/",
        "-v",
        "--tb=short",
        "--color=yes"
    ]
    return subprocess.run(cmd).returncode


def task_test_unit():
    """Run unit tests only"""
    print("🔬 Running unit tests...")
    cmd = [
        "python3", "-m", "pytest",
        "test/",
        "-v",
        "-m", "not integration and not functional and not security",
        "--tb=short",
        "--color=yes"
    ]
    return subprocess.run(cmd).returncode


def task_test_integration():
    """Run integration tests"""
    print("🔗 Running integration tests...")
    cmd = [
        "python3", "-m", "pytest",
        "test/", "spec/",
        "-v",
        "-m", "integration",
        "--tb=short",
        "--color=yes"
    ]
    return subprocess.run(cmd).returncode


def task_test_functional():
    """Run functional tests"""
    print("⚙️ Running functional tests...")
    cmd = [
        "python3", "-m", "pytest",
        "test/", "spec/",
        "-v",
        "-m", "functional",
        "--tb=short",
        "--color=yes"
    ]
    return subprocess.run(cmd).returncode


def task_test_security():
    """Run security-focused tests"""
    print("🔒 Running security tests...")
    cmd = [
        "python3", "-m", "pytest",
        "test/", "spec/",
        "-v",
        "-m", "security",
        "--tb=short",
        "--color=yes"
    ]
    return subprocess.run(cmd).returncode


def task_test_performance():
    """Run performance benchmarks"""
    print("⚡ Running performance tests...")
    cmd = [
        "python3", "-m", "pytest",
        "test/", "spec/",
        "-v",
        "-m", "performance",
        "--tb=short",
        "--color=yes"
    ]
    return subprocess.run(cmd).returncode


def task_test_coverage():
    """Run tests with coverage reporting"""
    print("📊 Running tests with coverage...")
    cmd = [
        "python3", "-m", "pytest",
        "test/", "spec/",
        "--cov=lib",
        "--cov=modules",
        "--cov=tools",
        "--cov-report=html:htmlcov",
        "--cov-report=term-missing",
        "--cov-report=xml",
        "-v",
        "--tb=short",
        "--color=yes"
    ]
    result = subprocess.run(cmd).returncode
    if result == 0:
        print("\n📈 Coverage report generated:")
        print("  - HTML: htmlcov/index.html")
        print("  - XML: coverage.xml")
    return result


def task_test_parallel():
    """Run tests in parallel"""
    print("🚀 Running tests in parallel...")
    cmd = [
        "python3", "-m", "pytest",
        "test/", "spec/",
        "-n", "auto",  # Use all available CPUs
        "-v",
        "--tb=short",
        "--color=yes"
    ]
    return subprocess.run(cmd).returncode


def task_test_quick():
    """Run quick smoke tests"""
    print("💨 Running quick smoke tests...")
    cmd = [
        "python3", "-m", "pytest",
        "test/",
        "-v",
        "-x",  # Stop on first failure
        "--tb=line",
        "--color=yes",
        "-k", "test_import or test_basic"  # Run only basic import/functionality tests
    ]
    return subprocess.run(cmd).returncode


def task_lint():
    """Run linters"""
    print("🔍 Running linters...")
    
    # Run flake8
    print("  Running flake8...")
    flake8_result = subprocess.run([
        "flake8", 
        "lib/", "modules/", "tools/", "test/", "spec/",
        "--max-line-length=120",
        "--ignore=E203,W503",  # Ignore conflicts with black
        "--exclude=__pycache__,*.pyc,.git,build,dist"
    ]).returncode
    
    # Run black check
    print("  Running black...")
    black_result = subprocess.run([
        "black", 
        "--check", 
        "--diff",
        "lib/", "modules/", "tools/", "test/", "spec/"
    ]).returncode
    
    # Run mypy (optional, may have many errors initially)
    print("  Running mypy (optional)...")
    mypy_result = subprocess.run([
        "mypy", 
        "lib/", "tools/",
        "--ignore-missing-imports",
        "--no-strict-optional"
    ]).returncode
    
    if flake8_result == 0 and black_result == 0:
        print("✅ All linting checks passed!")
        return 0
    else:
        print("❌ Some linting checks failed")
        return 1


def task_format():
    """Format code with black and isort"""
    print("🎨 Formatting code...")
    
    # Run black
    print("  Running black...")
    subprocess.run([
        "black", 
        "lib/", "modules/", "tools/", "test/", "spec/"
    ])
    
    # Run isort
    print("  Running isort...")
    subprocess.run([
        "isort", 
        "lib/", "modules/", "tools/", "test/", "spec/"
    ])
    
    print("✅ Code formatting complete!")
    return 0


def task_clean():
    """Clean build artifacts"""
    print("🧹 Cleaning build artifacts...")
    import shutil
    
    patterns = [
        "__pycache__", "*.pyc", "*.pyo", "*.pyd", 
        ".pytest_cache", "*.egg-info", ".coverage",
        "htmlcov", "coverage.xml", ".mypy_cache"
    ]
    
    cleaned = 0
    for pattern in patterns:
        for path in Path(".").rglob(pattern):
            try:
                if path.is_dir():
                    shutil.rmtree(path)
                    print(f"  Removed directory: {path}")
                else:
                    path.unlink()
                    print(f"  Removed file: {path}")
                cleaned += 1
            except Exception as e:
                print(f"  Warning: Could not remove {path}: {e}")
    
    print(f"✅ Cleaned {cleaned} artifacts")
    return 0


def task_install():
    """Install dependencies"""
    print("📦 Installing dependencies...")
    result = subprocess.run(["pip3", "install", "-r", "requirements.txt"]).returncode
    if result == 0:
        print("✅ Dependencies installed successfully!")
    else:
        print("❌ Failed to install dependencies")
    return result


def task_install_dev():
    """Install development dependencies"""
    print("🛠️ Installing development dependencies...")
    
    # Install main requirements
    result1 = subprocess.run(["pip3", "install", "-r", "requirements.txt"]).returncode
    
    # Install additional dev tools
    dev_packages = [
        "pytest-benchmark",
        "pytest-timeout",
        "pytest-randomly",
        "factory-boy",
        "freezegun",
        "responses"
    ]
    
    result2 = subprocess.run(["pip3", "install"] + dev_packages).returncode
    
    if result1 == 0 and result2 == 0:
        print("✅ Development dependencies installed successfully!")
        return 0
    else:
        print("❌ Failed to install some dependencies")
        return 1


def task_validate():
    """Validate the framework setup"""
    print("✅ Validating framework setup...")
    
    # Check Python version
    print(f"  Python version: {sys.version}")
    
    # Check critical imports
    critical_imports = [
        "pytest", "requests", "cryptography", "scapy", 
        "pwntools", "r2pipe", "yaml"
    ]
    
    failed_imports = []
    for module in critical_imports:
        try:
            __import__(module)
            print(f"  ✅ {module}")
        except ImportError:
            print(f"  ❌ {module}")
            failed_imports.append(module)
    
    # Check framework structure
    critical_paths = [
        "lib/", "modules/", "tools/", "test/", "spec/"
    ]
    
    missing_paths = []
    for path in critical_paths:
        if Path(path).exists():
            print(f"  ✅ {path}")
        else:
            print(f"  ❌ {path}")
            missing_paths.append(path)
    
    if failed_imports or missing_paths:
        print(f"\n❌ Validation failed:")
        if failed_imports:
            print(f"  Missing imports: {', '.join(failed_imports)}")
        if missing_paths:
            print(f"  Missing paths: {', '.join(missing_paths)}")
        return 1
    else:
        print("\n✅ Framework validation passed!")
        return 0


def main():
    """Main task runner"""
    tasks = {
        'test': task_test,
        'test-unit': task_test_unit,
        'test-integration': task_test_integration,
        'test-functional': task_test_functional,
        'test-security': task_test_security,
        'test-performance': task_test_performance,
        'test-coverage': task_test_coverage,
        'test-parallel': task_test_parallel,
        'test-quick': task_test_quick,
        'lint': task_lint,
        'format': task_format,
        'clean': task_clean,
        'install': task_install,
        'install-dev': task_install_dev,
        'validate': task_validate,
    }
    
    if len(sys.argv) < 2:
        print("🚀 Metasploit Framework Python Task Runner")
        print("\nAvailable tasks:")
        
        # Group tasks by category
        test_tasks = [k for k in tasks.keys() if k.startswith('test')]
        dev_tasks = [k for k in tasks.keys() if k in ['lint', 'format', 'clean']]
        setup_tasks = [k for k in tasks.keys() if k.startswith('install') or k == 'validate']
        
        print("\n📋 Testing:")
        for task in test_tasks:
            print(f"  - {task:<20} {tasks[task].__doc__}")
        
        print("\n🛠️ Development:")
        for task in dev_tasks:
            print(f"  - {task:<20} {tasks[task].__doc__}")
        
        print("\n⚙️ Setup:")
        for task in setup_tasks:
            print(f"  - {task:<20} {tasks[task].__doc__}")
        
        print(f"\nUsage: python3 {sys.argv[0]} <task_name>")
        sys.exit(0)
    
    task_name = sys.argv[1]
    if task_name in tasks:
        result = tasks[task_name]()
        sys.exit(result if result is not None else 0)
    else:
        print(f"❌ Unknown task: {task_name}")
        print(f"Available tasks: {', '.join(tasks.keys())}")
        sys.exit(1)


if __name__ == '__main__':
    main()
