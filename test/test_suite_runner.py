#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
Test Suite Runner and Coverage Reporter

Comprehensive test runner that organizes and executes all tests,
provides coverage reporting, and generates test reports.

Author: Metasploit Framework Python Migration Team
License: BSD-3-Clause
"""

import pytest
import sys
import os
import subprocess
from pathlib import Path
from typing import List, Dict, Optional
import argparse
import json
import time


class TestSuiteRunner:
    """Comprehensive test suite runner with coverage reporting."""
    
    def __init__(self, test_dir: str = None):
        self.test_dir = Path(test_dir) if test_dir else Path(__file__).parent
        self.project_root = self.test_dir.parent
        self.coverage_dir = self.test_dir / 'coverage'
        self.reports_dir = self.test_dir / 'reports'
        
        # Ensure directories exist
        self.coverage_dir.mkdir(exist_ok=True)
        self.reports_dir.mkdir(exist_ok=True)
    
    def discover_tests(self) -> Dict[str, List[str]]:
        """Discover all test files and categorize them."""
        test_categories = {
            'unit': [],
            'integration': [],
            'e2e': [],
            'performance': [],
            'security': []
        }
        
        # Find all test files
        for test_file in self.test_dir.glob('test_*.py'):
            if test_file.name == 'test_suite_runner.py':
                continue
                
            # Categorize based on file name and content
            if 'e2e' in test_file.name or 'playwright' in test_file.name:
                test_categories['e2e'].append(str(test_file))
            elif 'integration' in test_file.name:
                test_categories['integration'].append(str(test_file))
            elif 'performance' in test_file.name or 'perf' in test_file.name:
                test_categories['performance'].append(str(test_file))
            elif 'security' in test_file.name or 'sec' in test_file.name:
                test_categories['security'].append(str(test_file))
            else:
                test_categories['unit'].append(str(test_file))
        
        return test_categories
    
    def run_test_category(self, category: str, test_files: List[str], 
                         coverage: bool = True, verbose: bool = True) -> Dict:
        """Run tests for a specific category."""
        print(f"\n🧪 Running {category.upper()} tests...")
        print(f"   Files: {len(test_files)}")
        
        if not test_files:
            print(f"   No {category} tests found")
            return {'status': 'skipped', 'files': 0, 'tests': 0}
        
        # Build pytest command
        cmd = ['python', '-m', 'pytest']
        
        # Add coverage if requested
        if coverage:
            cmd.extend([
                '--cov=lib',
                '--cov=python_framework',
                '--cov=tools',
                f'--cov-report=html:{self.coverage_dir}/{category}',
                f'--cov-report=json:{self.coverage_dir}/{category}.json',
                '--cov-report=term-missing'
            ])
        
        # Add verbosity
        if verbose:
            cmd.append('-v')
        
        # Add test markers
        cmd.extend(['-m', category])
        
        # Add output options
        cmd.extend([
            '--tb=short',
            f'--junit-xml={self.reports_dir}/{category}_results.xml',
            f'--html={self.reports_dir}/{category}_report.html',
            '--self-contained-html'
        ])
        
        # Add test files
        cmd.extend(test_files)
        
        # Run tests
        start_time = time.time()
        try:
            result = subprocess.run(cmd, capture_output=True, text=True, 
                                  cwd=self.project_root)
            end_time = time.time()
            
            # Parse results
            return {
                'status': 'passed' if result.returncode == 0 else 'failed',
                'returncode': result.returncode,
                'duration': end_time - start_time,
                'stdout': result.stdout,
                'stderr': result.stderr,
                'files': len(test_files)
            }
            
        except Exception as e:
            end_time = time.time()
            return {
                'status': 'error',
                'error': str(e),
                'duration': end_time - start_time,
                'files': len(test_files)
            }
    
    def generate_coverage_report(self) -> Dict:
        """Generate comprehensive coverage report."""
        print("\n📊 Generating coverage report...")
        
        coverage_data = {}
        
        # Combine coverage from all categories
        for category in ['unit', 'integration', 'e2e']:
            coverage_file = self.coverage_dir / f'{category}.json'
            if coverage_file.exists():
                try:
                    with open(coverage_file, 'r') as f:
                        data = json.load(f)
                        coverage_data[category] = {
                            'percent_covered': data.get('totals', {}).get('percent_covered', 0),
                            'num_statements': data.get('totals', {}).get('num_statements', 0),
                            'missing_lines': data.get('totals', {}).get('missing_lines', 0)
                        }
                except Exception as e:
                    print(f"   Warning: Could not read {category} coverage: {e}")
        
        return coverage_data
    
    def run_all_tests(self, categories: List[str] = None, 
                     coverage: bool = True, verbose: bool = True) -> Dict:
        """Run all test categories."""
        if categories is None:
            categories = ['unit', 'integration', 'e2e']
        
        print("🚀 Starting comprehensive test suite...")
        print(f"   Categories: {', '.join(categories)}")
        print(f"   Coverage: {'enabled' if coverage else 'disabled'}")
        
        # Discover tests
        test_categories = self.discover_tests()
        
        # Run each category
        results = {}
        total_duration = 0
        
        for category in categories:
            if category in test_categories:
                result = self.run_test_category(
                    category, 
                    test_categories[category], 
                    coverage=coverage, 
                    verbose=verbose
                )
                results[category] = result
                total_duration += result.get('duration', 0)
                
                # Print summary
                status = result['status']
                duration = result.get('duration', 0)
                files = result.get('files', 0)
                
                status_emoji = {
                    'passed': '✅',
                    'failed': '❌', 
                    'error': '💥',
                    'skipped': '⏭️'
                }.get(status, '❓')
                
                print(f"   {status_emoji} {category.upper()}: {status} "
                      f"({files} files, {duration:.1f}s)")
        
        # Generate coverage report
        coverage_data = self.generate_coverage_report() if coverage else {}
        
        # Generate summary
        summary = {
            'total_duration': total_duration,
            'categories': results,
            'coverage': coverage_data,
            'timestamp': time.time()
        }
        
        # Save summary
        summary_file = self.reports_dir / 'test_summary.json'
        with open(summary_file, 'w') as f:
            json.dump(summary, f, indent=2)
        
        return summary
    
    def print_summary(self, summary: Dict):
        """Print test summary."""
        print("\n" + "="*60)
        print("📋 TEST SUMMARY")
        print("="*60)
        
        total_duration = summary['total_duration']
        categories = summary['categories']
        coverage = summary.get('coverage', {})
        
        # Overall status
        all_passed = all(result['status'] == 'passed' 
                        for result in categories.values())
        
        overall_emoji = '✅' if all_passed else '❌'
        print(f"{overall_emoji} Overall Status: {'PASSED' if all_passed else 'FAILED'}")
        print(f"⏱️  Total Duration: {total_duration:.1f}s")
        print()
        
        # Category details
        print("📊 Category Results:")
        for category, result in categories.items():
            status = result['status']
            duration = result.get('duration', 0)
            files = result.get('files', 0)
            
            status_emoji = {
                'passed': '✅',
                'failed': '❌',
                'error': '💥', 
                'skipped': '⏭️'
            }.get(status, '❓')
            
            print(f"   {status_emoji} {category.upper()}: {status} "
                  f"({files} files, {duration:.1f}s)")
        
        # Coverage summary
        if coverage:
            print("\n📈 Coverage Summary:")
            for category, cov_data in coverage.items():
                percent = cov_data.get('percent_covered', 0)
                statements = cov_data.get('num_statements', 0)
                missing = cov_data.get('missing_lines', 0)
                
                coverage_emoji = '🟢' if percent >= 80 else '🟡' if percent >= 60 else '🔴'
                print(f"   {coverage_emoji} {category.upper()}: {percent:.1f}% "
                      f"({statements} statements, {missing} missing)")
        
        print("\n📁 Reports generated in:", self.reports_dir)
        print("="*60)


def main():
    """Main entry point."""
    parser = argparse.ArgumentParser(
        description='Comprehensive Test Suite Runner',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  # Run all tests with coverage
  python test_suite_runner.py
  
  # Run only unit tests
  python test_suite_runner.py --categories unit
  
  # Run without coverage
  python test_suite_runner.py --no-coverage
  
  # Run specific categories
  python test_suite_runner.py --categories unit integration
        """
    )
    
    parser.add_argument(
        '--categories',
        nargs='+',
        choices=['unit', 'integration', 'e2e', 'performance', 'security'],
        default=['unit', 'integration', 'e2e'],
        help='Test categories to run'
    )
    
    parser.add_argument(
        '--no-coverage',
        action='store_true',
        help='Disable coverage reporting'
    )
    
    parser.add_argument(
        '--quiet',
        action='store_true',
        help='Reduce output verbosity'
    )
    
    parser.add_argument(
        '--test-dir',
        help='Test directory path (default: current directory)'
    )
    
    args = parser.parse_args()
    
    # Create runner
    runner = TestSuiteRunner(test_dir=args.test_dir)
    
    # Run tests
    summary = runner.run_all_tests(
        categories=args.categories,
        coverage=not args.no_coverage,
        verbose=not args.quiet
    )
    
    # Print summary
    runner.print_summary(summary)
    
    # Exit with appropriate code
    all_passed = all(result['status'] == 'passed' 
                    for result in summary['categories'].values())
    sys.exit(0 if all_passed else 1)


if __name__ == '__main__':
    main()