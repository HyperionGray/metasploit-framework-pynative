#!/usr/bin/env python3
"""
CI/CD Status Report Generator for Metasploit Framework

This script generates an accurate and comprehensive CI/CD review report,
addressing the issues found in the original report.
"""

import os
import sys
from pathlib import Path
from datetime import datetime
import subprocess
import json
from typing import Dict, List, Tuple, Optional


class CICDReportGenerator:
    """Generate comprehensive CI/CD status reports."""
    
    def __init__(self):
        self.root_path = Path(__file__).parent
        self.report_data = {
            'timestamp': datetime.utcnow().strftime("%Y-%m-%d %H:%M:%S UTC"),
            'repository': 'P4X-ng/metasploit-framework-pynative',
            'branch': 'master',
            'trigger': 'manual_validation'
        }
        
    def check_file_sizes(self) -> Dict[str, List[str]]:
        """Analyze file sizes and identify large files."""
        large_files = []
        
        # Common file extensions to check
        extensions = ['.py', '.rb', '.ts', '.js', '.cs', '.cpp', '.c', '.h']
        
        for ext in extensions:
            for file_path in self.root_path.rglob(f'*{ext}'):
                if file_path.is_file():
                    try:
                        line_count = len(file_path.read_text(encoding='utf-8', errors='ignore').splitlines())
                        if line_count > 500:
                            relative_path = file_path.relative_to(self.root_path)
                            large_files.append(f"{line_count} lines: ./{relative_path}")
                    except Exception:
                        continue
                        
        # Sort by line count (descending)
        large_files.sort(key=lambda x: int(x.split()[0]), reverse=True)
        
        return {
            'large_files': large_files[:25],  # Top 25 largest files
            'total_large_files': len(large_files)
        }
        
    def check_documentation(self) -> Dict[str, any]:
        """Check documentation completeness."""
        essential_docs = {
            'README.md': 'Project overview and usage',
            'CONTRIBUTING.md': 'Contribution guidelines',
            'LICENSE.md': 'License information',
            'CHANGELOG.md': 'Change history',
            'CODE_OF_CONDUCT.md': 'Code of conduct',
            'SECURITY.md': 'Security policy'
        }
        
        doc_status = {}
        readme_content_check = {}
        
        for doc_file, description in essential_docs.items():
            file_path = self.root_path / doc_file
            if file_path.exists():
                try:
                    content = file_path.read_text(encoding='utf-8')
                    word_count = len(content.split())
                    doc_status[doc_file] = {
                        'exists': True,
                        'word_count': word_count,
                        'description': description
                    }
                    
                    # Special check for README.md content
                    if doc_file == 'README.md':
                        content_lower = content.lower()
                        sections = [
                            'installation',
                            'usage',
                            'features',
                            'contributing',
                            'license',
                            'documentation',
                            'examples',
                            'api'
                        ]
                        
                        for section in sections:
                            readme_content_check[section] = section in content_lower
                            
                except Exception as e:
                    doc_status[doc_file] = {
                        'exists': True,
                        'error': str(e),
                        'description': description
                    }
            else:
                doc_status[doc_file] = {
                    'exists': False,
                    'description': description
                }
                
        return {
            'documentation_files': doc_status,
            'readme_content': readme_content_check
        }
        
    def run_build_validation(self) -> Dict[str, any]:
        """Run build validation and return results."""
        try:
            # Run the build validator script
            result = subprocess.run([
                sys.executable, 'build_validator.py'
            ], capture_output=True, text=True, cwd=self.root_path, timeout=300)
            
            build_success = result.returncode == 0
            
            # Try to load detailed results if available
            results_file = self.root_path / 'build_validation_results.json'
            detailed_results = None
            
            if results_file.exists():
                try:
                    with open(results_file, 'r') as f:
                        detailed_results = json.load(f)
                except Exception:
                    pass
                    
            return {
                'build_result': build_success,
                'build_output': result.stdout,
                'build_errors': result.stderr,
                'detailed_results': detailed_results
            }
            
        except subprocess.TimeoutExpired:
            return {
                'build_result': False,
                'build_output': '',
                'build_errors': 'Build validation timed out after 300 seconds',
                'detailed_results': None
            }
        except Exception as e:
            return {
                'build_result': False,
                'build_output': '',
                'build_errors': f'Build validation error: {e}',
                'detailed_results': None
            }
            
    def check_test_coverage(self) -> Dict[str, any]:
        """Check test coverage and framework integration."""
        test_info = {
            'test_files': [],
            'framework_tests': [],
            'playwright_integration': False
        }
        
        # Find test files
        test_dir = self.root_path / 'test'
        if test_dir.exists():
            for test_file in test_dir.glob('test_*.py'):
                try:
                    content = test_file.read_text(encoding='utf-8')
                    line_count = len(content.splitlines())
                    test_info['test_files'].append({
                        'name': test_file.name,
                        'lines': line_count,
                        'path': str(test_file.relative_to(self.root_path))
                    })
                    
                    # Check for Playwright integration
                    if 'playwright' in content.lower():
                        test_info['playwright_integration'] = True
                        
                except Exception:
                    continue
                    
        # Check for framework-specific tests
        framework_dir = self.root_path / 'python_framework'
        if framework_dir.exists():
            for test_file in framework_dir.rglob('test_*.py'):
                try:
                    content = test_file.read_text(encoding='utf-8')
                    line_count = len(content.splitlines())
                    test_info['framework_tests'].append({
                        'name': test_file.name,
                        'lines': line_count,
                        'path': str(test_file.relative_to(self.root_path))
                    })
                except Exception:
                    continue
                    
        return test_info
        
    def generate_report(self) -> str:
        """Generate the complete CI/CD report."""
        print("Generating CI/CD Status Report...")
        
        # Collect all data
        file_analysis = self.check_file_sizes()
        doc_analysis = self.check_documentation()
        build_results = self.run_build_validation()
        test_analysis = self.check_test_coverage()
        
        # Generate report
        report = f"""# Complete CI/CD Agent Review Report

**Review Date:** {self.report_data['timestamp']}
**Repository:** {self.report_data['repository']}
**Branch:** {self.report_data['branch']}
**Trigger:** {self.report_data['trigger']}

## Executive Summary

This comprehensive review covers:
- ✅ Code cleanliness and file size analysis
- ✅ Test coverage and framework integration
- ✅ Documentation completeness and quality
- ✅ Build functionality verification

## Detailed Findings

## Build Status

Build result: **{build_results['build_result']}**

"""
        
        # Add build details if available
        if build_results['detailed_results']:
            details = build_results['detailed_results']
            report += f"""### Build Validation Details

- **Overall Status:** {details.get('overall_status', 'UNKNOWN')}
- **Total Checks:** {details.get('summary', {}).get('total_checks', 0)}
- **Passed:** {details.get('summary', {}).get('passed', 0)}
- **Failed:** {details.get('summary', {}).get('failed', 0)}
- **Warnings:** {details.get('summary', {}).get('warned', 0)}
- **Success Rate:** {details.get('summary', {}).get('success_rate', '0%')}

"""
            
            if details.get('errors'):
                report += "### Build Errors\n\n"
                for error in details['errors']:
                    report += f"- {error}\n"
                report += "\n"
                
            if details.get('warnings'):
                report += "### Build Warnings\n\n"
                for warning in details['warnings']:
                    report += f"- {warning}\n"
                report += "\n"
        
        # Add file size analysis
        report += f"""## Code Cleanliness Analysis

### Large Files (>500 lines):
"""
        
        if file_analysis['large_files']:
            for file_info in file_analysis['large_files']:
                report += f"{file_info}\n"
        else:
            report += "No files larger than 500 lines found.\n"
            
        report += f"\n**Total large files:** {file_analysis['total_large_files']}\n\n"
        
        # Add documentation analysis
        report += """## Documentation Analysis

### Essential Documentation Files:
"""
        
        for doc_file, info in doc_analysis['documentation_files'].items():
            if info['exists']:
                if 'word_count' in info:
                    status = "✅"
                    detail = f"({info['word_count']} words)"
                else:
                    status = "⚠️"
                    detail = f"(error: {info.get('error', 'unknown')})"
            else:
                status = "❌"
                detail = "(missing)"
                
            report += f"{status} {doc_file} {detail}\n"
            
        # Add README content check
        if 'readme_content' in doc_analysis:
            report += "\n### README.md Content Check:\n"
            for section, present in doc_analysis['readme_content'].items():
                status = "✅" if present else "❌"
                report += f"{status} Contains '{section.title()}' section\n"
                
        # Add test coverage analysis
        report += f"""

## Test Coverage Analysis

### Test Files Found:
"""
        
        if test_analysis['test_files']:
            for test_file in test_analysis['test_files']:
                report += f"- **{test_file['name']}** ({test_file['lines']} lines)\n"
        else:
            report += "No test files found in test/ directory.\n"
            
        if test_analysis['framework_tests']:
            report += "\n### Framework-Specific Tests:\n"
            for test_file in test_analysis['framework_tests']:
                report += f"- **{test_file['name']}** ({test_file['lines']} lines)\n"
                
        playwright_status = "✅" if test_analysis['playwright_integration'] else "❌"
        report += f"\n### Playwright Integration: {playwright_status}\n"
        
        # Add action items
        report += """

## Action Items Summary

"""
        
        action_items = []
        
        # Check for build issues
        if not build_results['build_result']:
            action_items.append("- [ ] Fix build validation failures")
            
        # Check for missing documentation
        missing_docs = [doc for doc, info in doc_analysis['documentation_files'].items() 
                       if not info['exists']]
        if missing_docs:
            action_items.append(f"- [ ] Add missing documentation: {', '.join(missing_docs)}")
            
        # Check for large files
        if file_analysis['total_large_files'] > 20:
            action_items.append("- [ ] Review and potentially refactor large files")
            
        # Check for test coverage
        if not test_analysis['test_files']:
            action_items.append("- [ ] Add comprehensive test suite")
            
        if not test_analysis['playwright_integration']:
            action_items.append("- [ ] Consider adding Playwright integration for UI testing")
            
        if not action_items:
            action_items.append("- [x] All checks passed - no immediate action items")
            
        for item in action_items:
            report += f"{item}\n"
            
        report += """
---
*This report was automatically generated by the Enhanced CI/CD Review workflow.*
*For detailed build validation results, see build_validation_results.json*
"""
        
        return report
        
    def save_report(self, report: str, filename: str = 'cicd_status_report.md'):
        """Save the report to a file."""
        report_file = self.root_path / filename
        with open(report_file, 'w', encoding='utf-8') as f:
            f.write(report)
        print(f"Report saved to: {report_file}")
        return report_file


def main():
    """Main entry point."""
    generator = CICDReportGenerator()
    report = generator.generate_report()
    
    # Print report to console
    print("\n" + "="*80)
    print("CI/CD STATUS REPORT")
    print("="*80)
    print(report)
    
    # Save to file
    generator.save_report(report)
    
    print("\n✅ CI/CD Status Report Generated Successfully")


if __name__ == '__main__':
    main()