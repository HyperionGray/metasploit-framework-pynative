#!/usr/bin/env python3
"""
Architecture Analysis Script for Amazon Q Code Review
Analyzes design patterns, dependency management, and separation of concerns.
"""

import ast
import json
import os
import re
import subprocess
from datetime import datetime
from pathlib import Path
from typing import Dict, List, Any, Set
import argparse


class ArchitectureAnalyzer:
    """Analyzes code architecture and design patterns."""
    
    def __init__(self, repo_path: str = "."):
        self.repo_path = Path(repo_path)
        self.results = {}
        self.timestamp = datetime.utcnow().isoformat()
        
    def analyze_design_patterns(self) -> Dict[str, Any]:
        """Analyze usage of design patterns."""
        print("🏗️  Analyzing design patterns...")
        
        pattern_indicators = {
            "singleton": [
                r"class\s+\w+.*:\s*\n.*_instance\s*=\s*None",
                r"def\s+__new__\s*\(cls.*\):",
                r"if\s+cls\._instance\s+is\s+None:"
            ],
            "factory": [
                r"def\s+create_\w+\s*\(",
                r"class\s+\w*Factory\w*:",
                r"def\s+get_\w+\s*\(.*type.*\):"
            ],
            "observer": [
                r"def\s+notify\s*\(",
                r"def\s+subscribe\s*\(",
                r"def\s+unsubscribe\s*\(",
                r"observers\s*=\s*\[\]"
            ],
            "strategy": [
                r"class\s+\w*Strategy\w*:",
                r"def\s+set_strategy\s*\(",
                r"strategy\s*=\s*\w+"
            ]
        }
        
        findings = []
        python_files = list(self.repo_path.rglob("*.py"))
        
        for file_path in python_files:
            if self._should_skip_file(file_path):
                continue
                
            try:
                with open(file_path, 'r', encoding='utf-8') as f:
                    content = f.read()
                    
                for pattern_name, patterns in pattern_indicators.items():
                    pattern_count = 0
                    for pattern in patterns:
                        matches = re.findall(pattern, content, re.MULTILINE)
                        pattern_count += len(matches)
                    
                    if pattern_count >= 2:  # Likely pattern implementation
                        findings.append({
                            "file": str(file_path.relative_to(self.repo_path)),
                            "pattern": pattern_name,
                            "confidence": "high" if pattern_count >= 3 else "medium",
                            "indicators_found": pattern_count
                        })
            except Exception:
                continue
        
        return {
            "tool": "design_pattern_analysis",
            "status": "success",
            "findings": findings,
            "summary": f"Found {len(findings)} design pattern implementations"
        }
    
    def analyze_dependencies(self) -> Dict[str, Any]:
        """Analyze module dependencies and coupling."""
        print("🔗 Analyzing dependencies and coupling...")
        
        import_graph = {}
        circular_deps = []
        
        python_files = list(self.repo_path.rglob("*.py"))
        
        for file_path in python_files:
            if self._should_skip_file(file_path):
                continue
                
            try:
                with open(file_path, 'r', encoding='utf-8') as f:
                    content = f.read()
                
                # Parse imports
                tree = ast.parse(content)
                imports = []
                
                for node in ast.walk(tree):
                    if isinstance(node, ast.Import):
                        for alias in node.names:
                            imports.append(alias.name)
                    elif isinstance(node, ast.ImportFrom):
                        if node.module:
                            imports.append(node.module)
                
                module_name = str(file_path.relative_to(self.repo_path)).replace('/', '.').replace('.py', '')
                import_graph[module_name] = imports
                
            except Exception:
                continue
        
        # Detect circular dependencies (simplified)
        for module, deps in import_graph.items():
            for dep in deps:
                if dep in import_graph and module in import_graph[dep]:
                    circular_deps.append({
                        "module1": module,
                        "module2": dep,
                        "type": "circular_import"
                    })
        
        return {
            "tool": "dependency_analysis",
            "status": "success",
            "findings": {
                "total_modules": len(import_graph),
                "circular_dependencies": circular_deps,
                "highly_coupled_modules": self._find_highly_coupled(import_graph)
            },
            "summary": f"Analyzed {len(import_graph)} modules, found {len(circular_deps)} circular dependencies"
        }
    
    def analyze_separation_of_concerns(self) -> Dict[str, Any]:
        """Analyze separation of concerns in classes and modules."""
        print("🎯 Analyzing separation of concerns...")
        
        violations = []
        python_files = list(self.repo_path.rglob("*.py"))
        
        for file_path in python_files:
            if self._should_skip_file(file_path):
                continue
                
            try:
                with open(file_path, 'r', encoding='utf-8') as f:
                    content = f.read()
                
                tree = ast.parse(content)
                
                for node in ast.walk(tree):
                    if isinstance(node, ast.ClassDef):
                        methods = [n for n in node.body if isinstance(n, ast.FunctionDef)]
                        
                        # Check for classes with too many responsibilities
                        if len(methods) > 15:
                            violations.append({
                                "file": str(file_path.relative_to(self.repo_path)),
                                "class": node.name,
                                "issue": "too_many_methods",
                                "count": len(methods),
                                "severity": "medium"
                            })
                        
                        # Check for mixed concerns (e.g., UI + business logic)
                        method_names = [m.name for m in methods]
                        ui_methods = [m for m in method_names if any(ui in m.lower() for ui in ['render', 'display', 'show', 'print'])]
                        db_methods = [m for m in method_names if any(db in m.lower() for db in ['save', 'load', 'query', 'insert', 'update'])]
                        
                        if ui_methods and db_methods:
                            violations.append({
                                "file": str(file_path.relative_to(self.repo_path)),
                                "class": node.name,
                                "issue": "mixed_concerns",
                                "ui_methods": len(ui_methods),
                                "db_methods": len(db_methods),
                                "severity": "high"
                            })
                            
            except Exception:
                continue
        
        return {
            "tool": "separation_of_concerns_analysis",
            "status": "success",
            "findings": violations,
            "summary": f"Found {len(violations)} separation of concerns violations"
        }
    
    def _find_highly_coupled(self, import_graph: Dict[str, List[str]]) -> List[Dict[str, Any]]:
        """Find modules with high coupling (many dependencies)."""
        highly_coupled = []
        
        for module, deps in import_graph.items():
            # Filter internal dependencies
            internal_deps = [d for d in deps if not d.startswith(('os', 'sys', 'json', 'datetime', 'pathlib'))]
            
            if len(internal_deps) > 10:
                highly_coupled.append({
                    "module": module,
                    "dependency_count": len(internal_deps),
                    "dependencies": internal_deps[:5]  # Show first 5
                })
        
        return highly_coupled
    
    def _should_skip_file(self, file_path: Path) -> bool:
        """Check if file should be skipped."""
        skip_patterns = [
            "test", "tests", "spec", "__pycache__", 
            "venv", "virtualenv", "node_modules", 
            "build", "dist", "modules_legacy", "bak", "legacy"
        ]
        
        return any(pattern in str(file_path) for pattern in skip_patterns)
    
    def run_comprehensive_analysis(self) -> Dict[str, Any]:
        """Run all architecture analyses."""
        print("🚀 Starting comprehensive architecture analysis...")
        
        self.results = {
            "analysis_info": {
                "timestamp": self.timestamp,
                "repository": str(self.repo_path),
                "analyzer_version": "1.0.0"
            },
            "analyses": {}
        }
        
        # Run analyses
        analysis_functions = [
            ("design_patterns", self.analyze_design_patterns),
            ("dependencies", self.analyze_dependencies),
            ("separation_of_concerns", self.analyze_separation_of_concerns)
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
        """Generate architecture analysis summary."""
        summary = {
            "total_analyses": len(self.results["analyses"]),
            "successful_analyses": 0,
            "architecture_score": 0,
            "recommendations": []
        }
        
        total_issues = 0
        
        for analysis_name, analysis_result in self.results["analyses"].items():
            if analysis_result["status"] == "success":
                summary["successful_analyses"] += 1
                findings = analysis_result.get("findings", [])
                
                if isinstance(findings, list):
                    total_issues += len(findings)
                elif isinstance(findings, dict):
                    if "circular_dependencies" in findings:
                        total_issues += len(findings["circular_dependencies"])
        
        # Calculate architecture score (0-100)
        if total_issues == 0:
            summary["architecture_score"] = 100
        elif total_issues < 5:
            summary["architecture_score"] = 85
        elif total_issues < 15:
            summary["architecture_score"] = 70
        else:
            summary["architecture_score"] = max(50, 100 - total_issues * 2)
        
        # Generate recommendations
        if total_issues > 0:
            summary["recommendations"].extend([
                "Review and refactor classes with too many responsibilities",
                "Resolve circular dependencies between modules",
                "Implement proper design patterns where appropriate",
                "Improve separation of concerns in mixed-responsibility classes"
            ])
        
        return summary
    
    def save_results(self, output_file: str = "architecture_analysis_results.json"):
        """Save results to JSON file."""
        output_path = self.repo_path / output_file
        with open(output_path, 'w') as f:
            json.dump(self.results, f, indent=2)
        print(f"📄 Results saved to {output_path}")


def main():
    parser = argparse.ArgumentParser(description="Architecture Analysis for Amazon Q Code Review")
    parser.add_argument("--repo-path", default=".", help="Path to repository")
    parser.add_argument("--output", default="architecture_analysis_results.json", help="Output file")
    
    args = parser.parse_args()
    
    analyzer = ArchitectureAnalyzer(args.repo_path)
    results = analyzer.run_comprehensive_analysis()
    analyzer.save_results(args.output)
    
    # Print summary
    summary = results["summary"]
    print("\n" + "="*50)
    print("🏛️  ARCHITECTURE ANALYSIS SUMMARY")
    print("="*50)
    print(f"Architecture Score: {summary['architecture_score']}/100")
    print(f"Successful analyses: {summary['successful_analyses']}")
    
    if summary["recommendations"]:
        print("\n📋 RECOMMENDATIONS:")
        for i, rec in enumerate(summary["recommendations"], 1):
            print(f"{i}. {rec}")


if __name__ == "__main__":
    main()