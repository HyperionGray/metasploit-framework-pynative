#!/usr/bin/env python3
"""
Test Coverage Analysis Tool for Metasploit Framework

This tool helps identify Python files that lack test coverage and provides
recommendations for improving test coverage.

Usage:
    python3 scripts/check_test_coverage.py
    python3 scripts/check_test_coverage.py --directory lib/msf/core
    python3 scripts/check_test_coverage.py --report
"""

import os
import sys
import argparse
from pathlib import Path
from typing import List, Dict, Set, Tuple
import re


def find_python_files(directory: str, exclude_dirs: Set[str] = None) -> List[Path]:
    """
    Find all Python files in the given directory.
    
    Args:
        directory: Directory to search
        exclude_dirs: Set of directory names to exclude
    
    Returns:
        List of Path objects for Python files
    """
    if exclude_dirs is None:
        exclude_dirs = {'__pycache__', '.git', 'venv', 'virtualenv', 'dist', 'build', '.eggs'}
    
    python_files = []
    for root, dirs, files in os.walk(directory):
        # Remove excluded directories from the search
        dirs[:] = [d for d in dirs if d not in exclude_dirs]
        
        for file in files:
            if file.endswith('.py') and not file.startswith('test_'):
                python_files.append(Path(root) / file)
    
    return python_files


def find_test_files(test_directory: str = 'test') -> Set[str]:
    """
    Find all test files in the test directory.
    
    Args:
        test_directory: Root test directory
    
    Returns:
        Set of test file names
    """
    test_files = set()
    if not os.path.exists(test_directory):
        return test_files
    
    for root, dirs, files in os.walk(test_directory):
        for file in files:
            if file.endswith('.py') and (file.startswith('test_') or file.endswith('_test.py') or file.endswith('_spec.py')):
                test_files.add(file)
    
    return test_files


def guess_test_file_name(source_file: Path) -> List[str]:
    """
    Guess possible test file names for a source file.
    
    Args:
        source_file: Path to source file
    
    Returns:
        List of possible test file names
    """
    name = source_file.stem
    return [
        f'test_{name}.py',
        f'{name}_test.py',
        f'{name}_spec.py',
        f'test_{name}_comprehensive.py',
    ]


def check_has_test(source_file: Path, test_files: Set[str]) -> Tuple[bool, str]:
    """
    Check if a source file has a corresponding test file.
    
    Args:
        source_file: Path to source file
        test_files: Set of available test files
    
    Returns:
        Tuple of (has_test, test_file_name or '')
    """
    possible_names = guess_test_file_name(source_file)
    for name in possible_names:
        if name in test_files:
            return True, name
    return False, ''


def count_functions_and_classes(file_path: Path) -> Dict[str, int]:
    """
    Count the number of functions and classes in a Python file.
    
    Args:
        file_path: Path to Python file
    
    Returns:
        Dictionary with counts of functions and classes
    """
    try:
        with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
            content = f.read()
        
        # Count classes (excluding nested classes for simplicity)
        classes = len(re.findall(r'^\s*class\s+\w+', content, re.MULTILINE))
        
        # Count functions (excluding nested functions)
        functions = len(re.findall(r'^\s*def\s+\w+', content, re.MULTILINE))
        
        return {
            'classes': classes,
            'functions': functions,
            'lines': len(content.split('\n'))
        }
    except Exception as e:
        print(f"Warning: Could not analyze {file_path}: {e}", file=sys.stderr)
        return {'classes': 0, 'functions': 0, 'lines': 0}


def analyze_coverage(directory: str = '.', test_dir: str = 'test') -> Dict:
    """
    Analyze test coverage for Python files.
    
    Args:
        directory: Root directory to analyze
        test_dir: Test directory path
    
    Returns:
        Dictionary with coverage analysis results
    """
    print(f"Analyzing Python files in: {directory}")
    print(f"Looking for tests in: {test_dir}\n")
    
    # Find all Python source files
    python_files = find_python_files(directory)
    
    # Find all test files
    test_files = find_test_files(test_dir)
    
    # Analyze each file
    results = {
        'total_files': 0,
        'files_with_tests': 0,
        'files_without_tests': [],
        'total_classes': 0,
        'total_functions': 0,
        'total_lines': 0,
    }
    
    for py_file in python_files:
        # Skip test files and __init__.py
        if 'test' in str(py_file) or py_file.name == '__init__.py':
            continue
        
        results['total_files'] += 1
        
        # Check if file has tests
        has_test, test_name = check_has_test(py_file, test_files)
        
        # Count complexity
        stats = count_functions_and_classes(py_file)
        results['total_classes'] += stats['classes']
        results['total_functions'] += stats['functions']
        results['total_lines'] += stats['lines']
        
        if has_test:
            results['files_with_tests'] += 1
        else:
            # Only flag files that have actual code (not just imports)
            if stats['functions'] > 0 or stats['classes'] > 0:
                results['files_without_tests'].append({
                    'path': str(py_file),
                    'classes': stats['classes'],
                    'functions': stats['functions'],
                    'lines': stats['lines'],
                })
    
    return results


def print_report(results: Dict):
    """
    Print a formatted coverage report.
    
    Args:
        results: Results dictionary from analyze_coverage
    """
    print("=" * 80)
    print("TEST COVERAGE ANALYSIS REPORT")
    print("=" * 80)
    print()
    
    # Summary statistics
    print("Summary Statistics:")
    print("-" * 80)
    print(f"  Total Python files analyzed: {results['total_files']}")
    print(f"  Files with tests: {results['files_with_tests']}")
    print(f"  Files without tests: {len(results['files_without_tests'])}")
    
    if results['total_files'] > 0:
        coverage_pct = (results['files_with_tests'] / results['total_files']) * 100
        print(f"  Coverage: {coverage_pct:.1f}%")
    
    print(f"\n  Total classes: {results['total_classes']}")
    print(f"  Total functions: {results['total_functions']}")
    print(f"  Total lines of code: {results['total_lines']}")
    print()
    
    # Files without tests
    if results['files_without_tests']:
        print("\nFiles Without Tests (sorted by priority):")
        print("-" * 80)
        
        # Sort by priority: classes + functions (more code = higher priority)
        sorted_files = sorted(
            results['files_without_tests'],
            key=lambda x: (x['classes'] + x['functions'], x['lines']),
            reverse=True
        )
        
        print(f"{'Priority':<10} {'File':<50} {'Classes':<10} {'Functions':<12} {'Lines':<10}")
        print("-" * 80)
        
        for i, file_info in enumerate(sorted_files[:50], 1):  # Show top 50
            priority = 'HIGH' if i <= 10 else 'MEDIUM' if i <= 30 else 'LOW'
            path = file_info['path']
            if len(path) > 48:
                path = '...' + path[-45:]
            
            print(f"{priority:<10} {path:<50} {file_info['classes']:<10} "
                  f"{file_info['functions']:<12} {file_info['lines']:<10}")
        
        if len(sorted_files) > 50:
            print(f"\n  ... and {len(sorted_files) - 50} more files")
    else:
        print("\n✅ All files have corresponding test files!")
    
    print("\n" + "=" * 80)
    print("\nRecommendations:")
    print("-" * 80)
    print("1. Focus on HIGH priority files first (most classes/functions)")
    print("2. Create test files using naming convention: test_<module_name>.py")
    print("3. Aim for at least 80% code coverage for new/modified files")
    print("4. Use 'pytest --cov' to measure actual line coverage")
    print("5. See TESTING.md for testing guidelines and best practices")
    print()


def main():
    """Main entry point."""
    parser = argparse.ArgumentParser(
        description='Analyze test coverage for Python files in Metasploit Framework'
    )
    parser.add_argument(
        '--directory',
        '-d',
        default='.',
        help='Directory to analyze (default: current directory)'
    )
    parser.add_argument(
        '--test-dir',
        '-t',
        default='test',
        help='Test directory (default: test)'
    )
    parser.add_argument(
        '--report',
        '-r',
        action='store_true',
        help='Generate detailed report'
    )
    
    args = parser.parse_args()
    
    # Change to repository root if script is run from scripts directory
    if os.path.basename(os.getcwd()) == 'scripts':
        os.chdir('..')
    
    # Analyze coverage
    results = analyze_coverage(args.directory, args.test_dir)
    
    # Print report
    print_report(results)
    
    # Exit with appropriate code
    if results['files_without_tests']:
        sys.exit(1)  # Indicate there are files without tests
    else:
        sys.exit(0)  # All files have tests


if __name__ == '__main__':
    main()
