#!/usr/bin/env python3
"""
Performance Analysis Script for Amazon Q Code Review
Analyzes algorithm efficiency, resource management, and caching opportunities.
"""

import ast
import json
import os
import re
import subprocess
import sys
from datetime import datetime
from pathlib import Path
from typing import Dict, List, Any, Optional, Set
import argparse


class PerformanceAnalyzer:
    """Analyzes code for performance optimization opportunities."""
    
    def __init__(self, repo_path: str = "."):
        self.repo_path = Path(repo_path)
        self.results = {}
        self.timestamp = datetime.utcnow().isoformat()
        
    def analyze_algorithm_complexity(self) -> Dict[str, Any]:
        """Analyze code for potential O(n²) and inefficient patterns."""
        print("🔍 Analyzing algorithm complexity...")
        
        complexity_patterns = {
            "nested_loops": {
                "pattern": r"for\s+\w+\s+in\s+.*:\s*\n.*for\s+\w+\s+in\s+.*:",
                "description": "Nested loops - potential O(n²) complexity",
                "severity": "medium"
            },
            "list_comprehension_in_loop": {
                "pattern": r"for\s+\w+\s+in\s+.*:\s*\n.*\[.*for.*in.*\]",
                "description": "List comprehension inside loop - consider optimization",
                "severity": "low"
            },
            "repeated_string_concat": {
                "pattern": r"(\w+\s*\+=\s*.*str.*){3,}",
                "description": "Repeated string concatenation - use join() instead",
                "severity": "medium"
            },
            "inefficient_membership_test": {
                "pattern": r"if\s+\w+\s+in\s+\[.*\]:",
                "description": "Membership test on list - use set for better performance",
                "severity": "low"
            }
        }
        
        findings = []
        python_files = list(self.repo_path.rglob("*.py"))
        
        for file_path in python_files:
            if self._should_skip_file(file_path):
                continue
                
            try:
                with open(file_path, 'r', encoding='utf-8') as f:
                    content = f.read()
                    
                for pattern_name, pattern_info in complexity_patterns.items():
                    matches = re.finditer(pattern_info["pattern"], content, re.MULTILINE)
                    for match in matches:
                        line_num = content[:match.start()].count('\n') + 1
                        findings.append({
                            "file": str(file_path.relative_to(self.repo_path)),
                            "line": line_num,
                            "pattern": pattern_name,
                            "description": pattern_info["description"],
                            "severity": pattern_info["severity"],
                            "code_snippet": match.group(0)[:100]
                        })
            except Exception as e:
                continue
        
        return {
            "tool": "algorithm_complexity_analysis",
            "status": "success",
            "findings": findings,
            "summary": f"Found {len(findings)} potential complexity issues"
        }
    
    def analyze_memory_patterns(self) -> Dict[str, Any]:
        """Analyze code for potential memory leaks and resource management issues."""
        print("🧠 Analyzing memory usage patterns...")
        
        memory_patterns = {
            "unclosed_files": {
                "pattern": r"open\s*\([^)]+\)(?!\s*with)",
                "description": "File opened without context manager - potential resource leak",
                "severity": "high"
            },
            "large_data_structures": {
                "pattern": r"(\[\s*.*\s*for\s+.*\s+in\s+range\s*\(\s*\d{4,}\s*\)\s*\])",
                "description": "Large list comprehension - consider generator for memory efficiency",
                "severity": "medium"
            },
            "global_variables": {
                "pattern": r"^global\s+\w+",
                "description": "Global variable usage - potential memory retention",
                "severity": "low"
            },
            "circular_references": {
                "pattern": r"self\.\w+\s*=\s*self",
                "description": "Potential circular reference - check for memory leaks",
                "severity": "medium"
            }
        }
        
        findings = []
        python_files = list(self.repo_path.rglob("*.py"))
        
        for file_path in python_files:
            if self._should_skip_file(file_path):
                continue
                
            try:
                with open(file_path, 'r', encoding='utf-8') as f:
                    lines = f.readlines()
                    
                for line_num, line in enumerate(lines, 1):
                    for pattern_name, pattern_info in memory_patterns.items():
                        if re.search(pattern_info["pattern"], line):
                            findings.append({
                                "file": str(file_path.relative_to(self.repo_path)),
                                "line": line_num,
                                "pattern": pattern_name,
                                "description": pattern_info["description"],
                                "severity": pattern_info["severity"],
                                "code_snippet": line.strip()[:100]
                            })
            except Exception as e:
                continue
        
        return {
            "tool": "memory_analysis",
            "status": "success", 
            "findings": findings,
            "summary": f"Found {len(findings)} potential memory issues"
        }
    
    def analyze_caching_opportunities(self) -> Dict[str, Any]:
        """Identify opportunities for caching and memoization."""
        print("💾 Analyzing caching opportunities...")
        
        caching_patterns = {
            "repeated_computations": {
                "pattern": r"def\s+(\w+)\s*\([^)]*\):\s*\n.*return\s+.*\*\*.*",
                "description": "Expensive computation - consider caching results",
                "severity": "medium"
            },
            "database_queries_in_loop": {
                "pattern": r"for\s+\w+\s+in\s+.*:\s*\n.*\.execute\(",
                "description": "Database query in loop - consider batch operations",
                "severity": "high"
            },
            "file_operations_in_loop": {
                "pattern": r"for\s+\w+\s+in\s+.*:\s*\n.*open\(",
                "description": "File operations in loop - consider caching or batch processing",
                "severity": "medium"
            },
            "repeated_network_calls": {
                "pattern": r"for\s+\w+\s+in\s+.*:\s*\n.*requests\.(get|post)",
                "description": "Network calls in loop - consider caching or async processing",
                "severity": "high"
            }
        }
        
        findings = []
        python_files = list(self.repo_path.rglob("*.py"))
        
        for file_path in python_files:
            if self._should_skip_file(file_path):
                continue
                
            try:
                with open(file_path, 'r', encoding='utf-8') as f:
                    content = f.read()
                    
                for pattern_name, pattern_info in caching_patterns.items():
                    matches = re.finditer(pattern_info["pattern"], content, re.MULTILINE)
                    for match in matches:
                        line_num = content[:match.start()].count('\n') + 1
                        findings.append({
                            "file": str(file_path.relative_to(self.repo_path)),
                            "line": line_num,
                            "pattern": pattern_name,
                            "description": pattern_info["description"],
                            "severity": pattern_info["severity"],
                            "code_snippet": match.group(0)[:100]
                        })
            except Exception as e:
                continue
        
        return {
            "tool": "caching_analysis",
            "status": "success",
            "findings": findings,
            "summary": f"Found {len(findings)} caching opportunities"
        }
    
    def _should_skip_file(self, file_path: Path) -> bool:
        """Check if file should be skipped during analysis."""
        skip_patterns = [
            "test", "tests", "spec", "__pycache__", 
            "venv", "virtualenv", "node_modules", 
            "build", "dist", "modules_legacy", "bak", "legacy"
        ]
        
        return any(pattern in str(file_path) for pattern in skip_patterns)
    
    def run_comprehensive_analysis(self) -> Dict[str, Any]:
        """Run all performance analyses."""
        print("🚀 Starting comprehensive performance analysis...")
        
        self.results = {
            "analysis_info": {
                "timestamp": self.timestamp,
                "repository": str(self.repo_path),
                "analyzer_version": "1.0.0"
            },
            "analyses": {}
        }
        
        # Run all analyses
        analysis_functions = [
            ("algorithm_complexity", self.analyze_algorithm_complexity),
            ("memory_patterns", self.analyze_memory_patterns),
            ("caching_opportunities", self.analyze_caching_opportunities)
        ]
        
        for analysis_name, analysis_func in analysis_functions:
            try:
                self.results["analyses"][analysis_name] = analysis_func()
            except Exception as e:
                self.results["analyses"][analysis_name] = {
                    "tool": analysis_name,
                    "status": "error",
                    "message": f"Analysis failed: {str(e)}",
                    "findings": []
                }
        
        # Generate summary
        self.results["summary"] = self.generate_summary()
        
        return self.results
    
    def generate_summary(self) -> Dict[str, Any]:
        """Generate summary of performance analysis."""
        summary = {
            "total_analyses": len(self.results["analyses"]),
            "successful_analyses": 0,
            "failed_analyses": 0,
            "total_findings": 0,
            "high_priority_findings": 0,
            "optimization_opportunities": []
        }
        
        for analysis_name, analysis_result in self.results["analyses"].items():
            if analysis_result["status"] == "success":
                summary["successful_analyses"] += 1
                findings = analysis_result.get("findings", [])
                summary["total_findings"] += len(findings)
                
                # Count high priority findings
                high_priority = [f for f in findings if f.get("severity") == "high"]
                summary["high_priority_findings"] += len(high_priority)
            else:
                summary["failed_analyses"] += 1
        
        # Generate optimization recommendations
        if summary["total_findings"] > 0:
            summary["optimization_opportunities"].extend([
                "Review algorithm complexity in nested loops",
                "Implement proper resource management with context managers",
                "Add caching for expensive computations",
                "Consider async processing for I/O operations",
                "Use generators for large data processing"
            ])
        
        return summary
    
    def save_results(self, output_file: str = "performance_analysis_results.json"):
        """Save analysis results to JSON file."""
        output_path = self.repo_path / output_file
        with open(output_path, 'w') as f:
            json.dump(self.results, f, indent=2)
        print(f"📄 Results saved to {output_path}")


def main():
    parser = argparse.ArgumentParser(description="Performance Analysis for Amazon Q Code Review")
    parser.add_argument("--repo-path", default=".", help="Path to repository")
    parser.add_argument("--output", default="performance_analysis_results.json", help="Output file")
    
    args = parser.parse_args()
    
    analyzer = PerformanceAnalyzer(args.repo_path)
    results = analyzer.run_comprehensive_analysis()
    analyzer.save_results(args.output)
    
    # Print summary
    summary = results["summary"]
    print("\n" + "="*50)
    print("⚡ PERFORMANCE ANALYSIS SUMMARY")
    print("="*50)
    print(f"Total analyses: {summary['total_analyses']}")
    print(f"Successful: {summary['successful_analyses']}")
    print(f"Total findings: {summary['total_findings']}")
    print(f"High priority: {summary['high_priority_findings']}")
    
    if summary["optimization_opportunities"]:
        print("\n🎯 OPTIMIZATION OPPORTUNITIES:")
        for i, opp in enumerate(summary["optimization_opportunities"], 1):
            print(f"{i}. {opp}")


if __name__ == "__main__":
    main()