#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Task management for Metasploit Framework (converted from Rakefile)

Run tasks with: python3 tasks.py <task_name>
"""

import sys
import subprocess
from pathlib import Path


def task_test():
    """Run tests"""
    print("Running tests...")
    subprocess.run(["python3", "-m", "pytest", "test/"])


def task_lint():
    """Run linters"""
    print("Running linters...")
    subprocess.run(["flake8", "lib/", "modules/", "tools/"])


def task_clean():
    """Clean build artifacts"""
    print("Cleaning build artifacts...")
    import shutil
    patterns = ["__pycache__", "*.pyc", "*.pyo", "*.pyd", ".pytest_cache", "*.egg-info"]
    for pattern in patterns:
        for path in Path(".").rglob(pattern):
            if path.is_dir():
                shutil.rmtree(path)
            else:
                path.unlink()


def task_install():
    """Install dependencies"""
    print("Installing dependencies...")
    subprocess.run(["pip3", "install", "-r", "requirements.txt"])


def main():
    """Main task runner"""
    tasks = {
        'test': task_test,
        'lint': task_lint,
        'clean': task_clean,
        'install': task_install,
    }
    
    if len(sys.argv) < 2:
        print("Available tasks:")
        for task_name in tasks:
            print(f"  - {task_name}")
        sys.exit(0)
    
    task_name = sys.argv[1]
    if task_name in tasks:
        tasks[task_name]()
    else:
        print(f"Unknown task: {task_name}")
        sys.exit(1)


if __name__ == '__main__':
    main()
