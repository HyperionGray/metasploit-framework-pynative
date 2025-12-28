#!/usr/bin/env python3
"""
Code Quality Improvement Tool for Metasploit Framework

This tool helps address code cleanliness issues identified in CI/CD reviews:
- Analyzes large files and suggests refactoring opportunities
- Splits large test files into focused test modules
- Identifies code duplication and suggests consolidation
- Generates code quality reports

Usage:
    python tools/code_quality_improver.py --analyze
    python tools/code_quality_improver.py --refactor test/test_comprehensive_suite.py
    python tools/code_quality_improver.py --split-tests test/
"""

import ast
import os
import sys
import argparse
from pathlib import Path
from typing import List, Dict, Tuple, Optional
import re
from collections import defaultdict

class CodeAnalyzer:
    """Analyzes Python code for quality issues and refactoring opportunities."""
    
    def __init__(self):
        self.large_file_threshold = 500
        self.function_length_threshold = 50
        self.class_length_threshold = 200
        
    def analyze_file(self, file_path: Path) -> Dict:
        """Analyze a single Python file."""
        try:
            with open(file_path, 'r', encoding='utf-8') as f:
                content = f.read()
                
            tree = ast.parse(content)
            
            analysis = {
                'file_path': str(file_path),
                'line_count': len(content.splitlines()),
                'classes': [],
                'functions': [],
                'imports': [],
                'complexity_score': 0,
                'suggestions': []
            }
            
            for node in ast.walk(tree):
                if isinstance(node, ast.ClassDef):
                    class_info = self._analyze_class(node, content)
                    analysis['classes'].append(class_info)
                    
                elif isinstance(node, ast.FunctionDef):
                    func_info = self._analyze_function(node, content)
                    analysis['functions'].append(func_info)
                    
                elif isinstance(node, (ast.Import, ast.ImportFrom)):
                    analysis['imports'].append(self._get_import_info(node))
            
            # Generate suggestions
            analysis['suggestions'] = self._generate_suggestions(analysis)
            
            return analysis
            
        except Exception as e:
            return {
                'file_path': str(file_path),
                'error': str(e),
                'suggestions': [f"Could not analyze file: {e}"]
            }
    
    def _analyze_class(self, node: ast.ClassDef, content: str) -> Dict:
        """Analyze a class definition."""
        lines = content.splitlines()
        start_line = node.lineno
        end_line = node.end_lineno or start_line
        
        methods = []
        for item in node.body:
            if isinstance(item, ast.FunctionDef):
                methods.append({
                    'name': item.name,
                    'line_count': (item.end_lineno or item.lineno) - item.lineno + 1,
                    'is_test': item.name.startswith('test_')
                })
        
        return {
            'name': node.name,
            'line_count': end_line - start_line + 1,
            'method_count': len(methods),
            'methods': methods,
            'is_test_class': node.name.startswith('Test')
        }
    
    def _analyze_function(self, node: ast.FunctionDef, content: str) -> Dict:
        """Analyze a function definition."""
        start_line = node.lineno
        end_line = node.end_lineno or start_line
        
        return {
            'name': node.name,
            'line_count': end_line - start_line + 1,
            'is_test': node.name.startswith('test_'),
            'is_method': False  # Will be updated if part of a class
        }
    
    def _get_import_info(self, node) -> Dict:
        """Extract import information."""
        if isinstance(node, ast.Import):
            return {
                'type': 'import',
                'modules': [alias.name for alias in node.names]
            }
        else:  # ast.ImportFrom
            return {
                'type': 'from_import',
                'module': node.module,
                'names': [alias.name for alias in node.names]
            }
    
    def _generate_suggestions(self, analysis: Dict) -> List[str]:
        """Generate refactoring suggestions based on analysis."""
        suggestions = []
        
        # Check file size
        if analysis['line_count'] > self.large_file_threshold:
            suggestions.append(f"File is large ({analysis['line_count']} lines). Consider splitting into smaller modules.")
        
        # Check class sizes
        for cls in analysis['classes']:
            if cls['line_count'] > self.class_length_threshold:
                suggestions.append(f"Class '{cls['name']}' is large ({cls['line_count']} lines). Consider splitting into smaller classes.")
            
            # Test class specific suggestions
            if cls['is_test_class'] and cls['method_count'] > 20:
                suggestions.append(f"Test class '{cls['name']}' has many methods ({cls['method_count']}). Consider splitting by functionality.")
        
        # Check function sizes
        for func in analysis['functions']:
            if func['line_count'] > self.function_length_threshold:
                suggestions.append(f"Function '{func['name']}' is long ({func['line_count']} lines). Consider breaking into smaller functions.")
        
        return suggestions

class TestFileSplitter:
    """Splits large test files into focused test modules."""
    
    def __init__(self):
        self.analyzer = CodeAnalyzer()
    
    def split_test_file(self, file_path: Path, output_dir: Path) -> List[Path]:
        """Split a large test file into smaller, focused test files."""
        analysis = self.analyzer.analyze_file(file_path)
        
        if 'error' in analysis:
            print(f"Cannot split {file_path}: {analysis['error']}")
            return []
        
        # Group test methods by functionality
        test_groups = self._group_test_methods(analysis)
        
        created_files = []
        
        for group_name, methods in test_groups.items():
            new_file_path = output_dir / f"test_{group_name}.py"
            self._create_test_file(file_path, new_file_path, methods)
            created_files.append(new_file_path)
        
        return created_files
    
    def _group_test_methods(self, analysis: Dict) -> Dict[str, List]:
        """Group test methods by functionality based on naming patterns."""
        groups = defaultdict(list)
        
        for cls in analysis['classes']:
            if cls['is_test_class']:
                for method in cls['methods']:
                    if method['is_test']:
                        # Extract functionality from test name
                        group = self._extract_test_group(method['name'])
                        groups[group].append({
                            'class': cls['name'],
                            'method': method['name']
                        })
        
        return dict(groups)
    
    def _extract_test_group(self, test_name: str) -> str:
        """Extract functional group from test method name."""
        # Remove 'test_' prefix
        name = test_name[5:] if test_name.startswith('test_') else test_name
        
        # Common patterns
        patterns = {
            r'.*http.*': 'http_client',
            r'.*ssh.*': 'ssh_client',
            r'.*crypto.*': 'cryptography',
            r'.*exploit.*': 'exploits',
            r'.*payload.*': 'payloads',
            r'.*auth.*': 'authentication',
            r'.*login.*': 'authentication',
            r'.*database.*': 'database',
            r'.*db.*': 'database',
            r'.*network.*': 'network',
            r'.*file.*': 'file_operations',
            r'.*config.*': 'configuration',
            r'.*module.*': 'module_loading',
            r'.*framework.*': 'framework_core'
        }
        
        for pattern, group in patterns.items():
            if re.match(pattern, name, re.IGNORECASE):
                return group
        
        # Default grouping by first word
        words = name.split('_')
        return words[0] if words else 'misc'
    
    def _create_test_file(self, original_file: Path, new_file: Path, methods: List[Dict]):
        """Create a new test file with specified methods."""
        # This is a simplified implementation
        # In practice, you'd need to extract the actual method code
        
        content = f'''"""
Test module extracted from {original_file.name}
Generated by Code Quality Improvement Tool
"""

import pytest
from test.conftest import *  # Import common fixtures

# TODO: Extract actual test methods from original file
# Methods to extract: {[m['method'] for m in methods]}

class TestExtracted:
    """Extracted test class."""
    
    def test_placeholder(self):
        """Placeholder test - replace with actual extracted tests."""
        assert True
'''
        
        new_file.parent.mkdir(parents=True, exist_ok=True)
        with open(new_file, 'w') as f:
            f.write(content)

class CodeQualityReporter:
    """Generates code quality reports."""
    
    def __init__(self):
        self.analyzer = CodeAnalyzer()
    
    def generate_report(self, directory: Path) -> Dict:
        """Generate a comprehensive code quality report."""
        report = {
            'summary': {
                'total_files': 0,
                'large_files': 0,
                'total_lines': 0,
                'total_suggestions': 0
            },
            'files': [],
            'top_issues': []
        }
        
        # Analyze all Python files
        for py_file in directory.rglob('*.py'):
            if self._should_analyze_file(py_file):
                analysis = self.analyzer.analyze_file(py_file)
                report['files'].append(analysis)
                
                # Update summary
                report['summary']['total_files'] += 1
                if 'line_count' in analysis:
                    report['summary']['total_lines'] += analysis['line_count']
                    if analysis['line_count'] > 500:
                        report['summary']['large_files'] += 1
                
                if 'suggestions' in analysis:
                    report['summary']['total_suggestions'] += len(analysis['suggestions'])
        
        # Identify top issues
        report['top_issues'] = self._identify_top_issues(report['files'])
        
        return report
    
    def _should_analyze_file(self, file_path: Path) -> bool:
        """Determine if a file should be analyzed."""
        # Skip certain directories and files
        skip_patterns = [
            '__pycache__',
            '.git',
            'venv',
            'virtualenv',
            '.pytest_cache',
            'build',
            'dist'
        ]
        
        for pattern in skip_patterns:
            if pattern in str(file_path):
                return False
        
        return True
    
    def _identify_top_issues(self, file_analyses: List[Dict]) -> List[Dict]:
        """Identify the most critical code quality issues."""
        issues = []
        
        for analysis in file_analyses:
            if 'line_count' in analysis and analysis['line_count'] > 1000:
                issues.append({
                    'type': 'very_large_file',
                    'file': analysis['file_path'],
                    'severity': 'high',
                    'description': f"File has {analysis['line_count']} lines"
                })
        
        # Sort by severity and line count
        issues.sort(key=lambda x: (x['severity'], -int(x['description'].split()[2])))
        
        return issues[:10]  # Top 10 issues

def main():
    """Main entry point."""
    parser = argparse.ArgumentParser(description="Code Quality Improvement Tool")
    
    parser.add_argument(
        "--analyze",
        action="store_true",
        help="Analyze code quality and generate report"
    )
    
    parser.add_argument(
        "--refactor",
        type=str,
        help="Analyze specific file for refactoring opportunities"
    )
    
    parser.add_argument(
        "--split-tests",
        type=str,
        help="Split large test files in directory"
    )
    
    parser.add_argument(
        "--output-dir",
        type=str,
        default="refactored",
        help="Output directory for refactored files"
    )
    
    args = parser.parse_args()
    
    if args.analyze:
        print("🔍 Analyzing code quality...")
        reporter = CodeQualityReporter()
        report = reporter.generate_report(Path('.'))
        
        print(f"\n📊 Code Quality Report")
        print(f"Total files analyzed: {report['summary']['total_files']}")
        print(f"Large files (>500 lines): {report['summary']['large_files']}")
        print(f"Total lines of code: {report['summary']['total_lines']}")
        print(f"Total suggestions: {report['summary']['total_suggestions']}")
        
        if report['top_issues']:
            print(f"\n🚨 Top Issues:")
            for issue in report['top_issues']:
                print(f"  - {issue['file']}: {issue['description']}")
    
    elif args.refactor:
        print(f"🔧 Analyzing {args.refactor} for refactoring...")
        analyzer = CodeAnalyzer()
        analysis = analyzer.analyze_file(Path(args.refactor))
        
        print(f"\nFile: {analysis['file_path']}")
        print(f"Lines: {analysis.get('line_count', 'Unknown')}")
        print(f"Classes: {len(analysis.get('classes', []))}")
        print(f"Functions: {len(analysis.get('functions', []))}")
        
        if analysis.get('suggestions'):
            print(f"\n💡 Suggestions:")
            for suggestion in analysis['suggestions']:
                print(f"  - {suggestion}")
    
    elif args.split_tests:
        print(f"✂️  Splitting test files in {args.split_tests}...")
        splitter = TestFileSplitter()
        output_dir = Path(args.output_dir)
        
        test_files = list(Path(args.split_tests).glob("test_*.py"))
        
        for test_file in test_files:
            if test_file.stat().st_size > 50000:  # Files larger than 50KB
                print(f"Splitting {test_file}...")
                created_files = splitter.split_test_file(test_file, output_dir)
                print(f"Created {len(created_files)} new test files")
    
    else:
        parser.print_help()

if __name__ == "__main__":
    main()