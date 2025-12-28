#!/usr/bin/env python3
"""
Code Quality Assessment Tool
Analyzes the quality of converted Ruby-to-Python code
"""

import os
import ast
import re
from pathlib import Path
import json
from collections import defaultdict
from datetime import datetime

class CodeQualityAnalyzer:
    def __init__(self):
        self.results = {
            'timestamp': datetime.now().isoformat(),
            'analysis': {},
            'summary': {
                'files_analyzed': 0,
                'total_lines': 0,
                'todo_count': 0,
                'syntax_errors': 0,
                'quality_score': 0
            },
            'issues': []
        }
        
    def analyze_python_file(self, file_path):
        """Analyze a single Python file for quality issues"""
        try:
            with open(file_path, 'r', encoding='utf-8') as f:
                content = f.read()
                
            analysis = {
                'path': str(file_path),
                'lines': len(content.splitlines()),
                'size_bytes': len(content),
                'issues': []
            }
            
            # Check for syntax errors
            try:
                ast.parse(content)
                analysis['syntax_valid'] = True
            except SyntaxError as e:
                analysis['syntax_valid'] = False
                analysis['syntax_error'] = str(e)
                self.results['summary']['syntax_errors'] += 1
                
            # Check for TODO comments
            todo_pattern = r'#.*?TODO|#.*?FIXME|#.*?XXX|#.*?HACK'
            todos = re.findall(todo_pattern, content, re.IGNORECASE)
            analysis['todo_count'] = len(todos)
            analysis['todos'] = todos[:5]  # First 5 TODOs
            self.results['summary']['todo_count'] += len(todos)
            
            # Check for conversion artifacts
            conversion_artifacts = [
                r'# Converted from Ruby',
                r'# TODO.*convert',
                r'# Ruby.*Python',
                r'raise NotImplementedError',
                r'pass\s*#.*implement'
            ]
            
            artifacts_found = []
            for pattern in conversion_artifacts:
                matches = re.findall(pattern, content, re.IGNORECASE)
                if matches:
                    artifacts_found.extend(matches)
                    
            analysis['conversion_artifacts'] = len(artifacts_found)
            analysis['artifact_examples'] = artifacts_found[:3]
            
            # Check for code quality indicators
            quality_indicators = {
                'has_docstrings': bool(re.search(r'""".*?"""', content, re.DOTALL)),
                'has_type_hints': bool(re.search(r':\s*\w+\s*=|def.*?\(.*?:\s*\w+', content)),
                'has_imports': bool(re.search(r'^import |^from .* import', content, re.MULTILINE)),
                'has_classes': bool(re.search(r'^class \w+', content, re.MULTILINE)),
                'has_functions': bool(re.search(r'^def \w+', content, re.MULTILINE)),
                'has_main_guard': bool(re.search(r'if __name__ == ["\']__main__["\']:', content))
            }
            
            analysis['quality_indicators'] = quality_indicators
            
            # Calculate quality score (0-100)
            score = 0
            if analysis['syntax_valid']:
                score += 30
            if quality_indicators['has_docstrings']:
                score += 15
            if quality_indicators['has_type_hints']:
                score += 15
            if quality_indicators['has_classes'] or quality_indicators['has_functions']:
                score += 20
            if analysis['todo_count'] == 0:
                score += 10
            if analysis['conversion_artifacts'] == 0:
                score += 10
                
            analysis['quality_score'] = score
            
            return analysis
            
        except Exception as e:
            return {
                'path': str(file_path),
                'error': str(e),
                'quality_score': 0
            }
    
    def analyze_directory(self, directory, pattern="*.py", max_files=100):
        """Analyze Python files in a directory"""
        dir_path = Path(directory)
        if not dir_path.exists():
            return
            
        python_files = list(dir_path.rglob(pattern))[:max_files]
        
        print(f"Analyzing {len(python_files)} Python files in {directory}...")
        
        for file_path in python_files:
            if file_path.is_file():
                analysis = self.analyze_python_file(file_path)
                self.results['analysis'][str(file_path)] = analysis
                self.results['summary']['files_analyzed'] += 1
                self.results['summary']['total_lines'] += analysis.get('lines', 0)
                
                # Track significant issues
                if analysis.get('syntax_valid') == False:
                    self.results['issues'].append({
                        'type': 'syntax_error',
                        'file': str(file_path),
                        'message': analysis.get('syntax_error', 'Unknown syntax error')
                    })
                    
                if analysis.get('todo_count', 0) > 5:
                    self.results['issues'].append({
                        'type': 'high_todo_count',
                        'file': str(file_path),
                        'count': analysis['todo_count']
                    })
                    
                if analysis.get('conversion_artifacts', 0) > 3:
                    self.results['issues'].append({
                        'type': 'conversion_artifacts',
                        'file': str(file_path),
                        'count': analysis['conversion_artifacts']
                    })
    
    def analyze_key_components(self):
        """Analyze key framework components"""
        key_components = [
            ('Main Executables', '.', 'msf*'),
            ('Python Framework Core', 'python_framework', '*.py'),
            ('Exploit Modules', 'modules/exploits', '*.py'),
            ('Auxiliary Modules', 'modules/auxiliary', '*.py'),
            ('Library Files', 'lib', '*.py'),
            ('Tools', 'tools', '*.py')
        ]
        
        for name, directory, pattern in key_components:
            print(f"\n=== Analyzing {name} ===")
            if Path(directory).exists():
                self.analyze_directory(directory, pattern, max_files=20)
            else:
                print(f"Directory {directory} not found")
    
    def generate_report(self):
        """Generate comprehensive quality report"""
        if self.results['summary']['files_analyzed'] == 0:
            print("No files analyzed")
            return
            
        # Calculate overall quality score
        total_score = sum(
            analysis.get('quality_score', 0) 
            for analysis in self.results['analysis'].values()
        )
        avg_score = total_score / self.results['summary']['files_analyzed']
        self.results['summary']['quality_score'] = round(avg_score, 1)
        
        print("\n" + "=" * 60)
        print("CODE QUALITY ASSESSMENT REPORT")
        print("=" * 60)
        
        print(f"Files Analyzed: {self.results['summary']['files_analyzed']}")
        print(f"Total Lines of Code: {self.results['summary']['total_lines']:,}")
        print(f"Syntax Errors: {self.results['summary']['syntax_errors']}")
        print(f"TODO Comments: {self.results['summary']['todo_count']}")
        print(f"Overall Quality Score: {self.results['summary']['quality_score']}/100")
        
        # Quality assessment
        if avg_score >= 80:
            quality_level = "EXCELLENT"
        elif avg_score >= 60:
            quality_level = "GOOD"
        elif avg_score >= 40:
            quality_level = "FAIR"
        else:
            quality_level = "POOR"
            
        print(f"Quality Level: {quality_level}")
        
        # Top issues
        print(f"\nTop Issues Found: {len(self.results['issues'])}")
        for issue in self.results['issues'][:10]:
            print(f"  - {issue['type']}: {issue['file']}")
            
        # Files with highest TODO counts
        high_todo_files = [
            (path, analysis.get('todo_count', 0))
            for path, analysis in self.results['analysis'].items()
            if analysis.get('todo_count', 0) > 0
        ]
        high_todo_files.sort(key=lambda x: x[1], reverse=True)
        
        if high_todo_files:
            print(f"\nFiles with Most TODOs:")
            for file_path, todo_count in high_todo_files[:5]:
                print(f"  - {Path(file_path).name}: {todo_count} TODOs")
        
        # Files with conversion artifacts
        artifact_files = [
            (path, analysis.get('conversion_artifacts', 0))
            for path, analysis in self.results['analysis'].items()
            if analysis.get('conversion_artifacts', 0) > 0
        ]
        
        if artifact_files:
            print(f"\nFiles with Conversion Artifacts: {len(artifact_files)}")
            
        # Save detailed results
        with open('code_quality_results.json', 'w') as f:
            json.dump(self.results, f, indent=2)
            
        print(f"\nDetailed results saved to: code_quality_results.json")
        
        return self.results

if __name__ == "__main__":
    analyzer = CodeQualityAnalyzer()
    analyzer.analyze_key_components()
    analyzer.generate_report()