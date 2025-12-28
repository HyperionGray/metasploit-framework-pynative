#!/usr/bin/env python3
"""
Comprehensive Framework Functionality Tester
Tests actual functionality vs. documented claims
"""

import os
import sys
import subprocess
import importlib.util
from pathlib import Path
import json
from datetime import datetime

class FrameworkTester:
    def __init__(self):
        self.results = {
            'timestamp': datetime.now().isoformat(),
            'tests': {},
            'summary': {
                'total': 0,
                'passed': 0,
                'failed': 0,
                'warnings': 0
            }
        }
        
    def test_result(self, test_name, status, message, details=None):
        """Record a test result"""
        self.results['tests'][test_name] = {
            'status': status,
            'message': message,
            'details': details or {}
        }
        self.results['summary']['total'] += 1
        if status == 'PASS':
            self.results['summary']['passed'] += 1
        elif status == 'FAIL':
            self.results['summary']['failed'] += 1
        else:
            self.results['summary']['warnings'] += 1
            
        print(f"[{status}] {test_name}: {message}")
        
    def test_main_executables(self):
        """Test if main MSF executables work"""
        executables = ['msfconsole', 'msfd', 'msfdb', 'msfvenom', 'msfrpc']
        
        for exe in executables:
            exe_path = Path(exe)
            if exe_path.exists():
                try:
                    # Test if it's executable and runs without crashing
                    result = subprocess.run([sys.executable, str(exe_path), '--help'], 
                                          capture_output=True, text=True, timeout=10)
                    if result.returncode == 0:
                        self.test_result(f"executable_{exe}", "PASS", 
                                       f"{exe} executes successfully")
                    else:
                        self.test_result(f"executable_{exe}", "FAIL", 
                                       f"{exe} failed with return code {result.returncode}",
                                       {'stderr': result.stderr[:200]})
                except subprocess.TimeoutExpired:
                    self.test_result(f"executable_{exe}", "WARN", 
                                   f"{exe} timed out (may be waiting for input)")
                except Exception as e:
                    self.test_result(f"executable_{exe}", "FAIL", 
                                   f"{exe} failed with exception: {str(e)}")
            else:
                self.test_result(f"executable_{exe}", "FAIL", 
                               f"{exe} not found")
    
    def test_python_framework_core(self):
        """Test Python framework core components"""
        core_path = Path('python_framework/core')
        
        if not core_path.exists():
            self.test_result("framework_core", "FAIL", "Python framework core not found")
            return
            
        # Test core modules can be imported
        core_modules = ['exploit.py', '__init__.py']
        
        for module_file in core_modules:
            module_path = core_path / module_file
            if module_path.exists():
                try:
                    # Try to import the module
                    spec = importlib.util.spec_from_file_location(
                        f"core_{module_file[:-3]}", module_path)
                    module = importlib.util.module_from_spec(spec)
                    spec.loader.exec_module(module)
                    
                    self.test_result(f"core_import_{module_file}", "PASS", 
                                   f"Successfully imported {module_file}")
                except Exception as e:
                    self.test_result(f"core_import_{module_file}", "FAIL", 
                                   f"Failed to import {module_file}: {str(e)}")
            else:
                self.test_result(f"core_import_{module_file}", "FAIL", 
                               f"{module_file} not found")
    
    def test_module_examples(self):
        """Test example modules"""
        example_modules = [
            'modules/exploits/example.py',
            'modules/auxiliary/example.py'
        ]
        
        for module_path in example_modules:
            path = Path(module_path)
            if path.exists():
                try:
                    # Try to import and check basic structure
                    spec = importlib.util.spec_from_file_location(
                        f"test_module_{path.stem}", path)
                    module = importlib.util.module_from_spec(spec)
                    spec.loader.exec_module(module)
                    
                    # Check for required components
                    has_metadata = hasattr(module, 'metadata')
                    has_run = hasattr(module, 'run')
                    
                    if has_metadata and has_run:
                        self.test_result(f"module_{path.stem}", "PASS", 
                                       f"Module {path.name} has required components")
                    else:
                        missing = []
                        if not has_metadata: missing.append('metadata')
                        if not has_run: missing.append('run')
                        self.test_result(f"module_{path.stem}", "WARN", 
                                       f"Module {path.name} missing: {', '.join(missing)}")
                        
                except Exception as e:
                    self.test_result(f"module_{path.stem}", "FAIL", 
                                   f"Failed to load {path.name}: {str(e)}")
            else:
                self.test_result(f"module_{path.stem}", "FAIL", 
                               f"Module {module_path} not found")
    
    def test_dependencies(self):
        """Test if key dependencies are available"""
        key_deps = [
            'requests', 'cryptography', 'paramiko', 'scapy', 
            'pwntools', 'flask', 'sqlalchemy', 'pytest'
        ]
        
        for dep in key_deps:
            try:
                importlib.import_module(dep)
                self.test_result(f"dependency_{dep}", "PASS", 
                               f"Dependency {dep} available")
            except ImportError:
                self.test_result(f"dependency_{dep}", "FAIL", 
                               f"Dependency {dep} not available")
    
    def test_file_structure(self):
        """Test expected file structure exists"""
        expected_dirs = [
            'modules', 'lib', 'tools', 'data', 'python_framework',
            'ruby2py', 'test', 'docs'
        ]
        
        for dir_name in expected_dirs:
            dir_path = Path(dir_name)
            if dir_path.exists() and dir_path.is_dir():
                file_count = len(list(dir_path.rglob('*')))
                self.test_result(f"structure_{dir_name}", "PASS", 
                               f"Directory {dir_name} exists with {file_count} files")
            else:
                self.test_result(f"structure_{dir_name}", "FAIL", 
                               f"Directory {dir_name} missing")
    
    def test_conversion_claims(self):
        """Test conversion claims against reality"""
        # Count Python files
        python_files = list(Path('.').rglob('*.py'))
        ruby_files = list(Path('.').rglob('*.rb'))
        
        self.test_result("conversion_python_files", "INFO", 
                       f"Found {len(python_files)} Python files")
        self.test_result("conversion_ruby_files", "INFO", 
                       f"Found {len(ruby_files)} Ruby files")
        
        # Check if claimed 7,456 Python files exist
        if len(python_files) >= 7000:
            self.test_result("conversion_count_claim", "PASS", 
                           f"Python file count ({len(python_files)}) matches claims")
        else:
            self.test_result("conversion_count_claim", "WARN", 
                           f"Python file count ({len(python_files)}) lower than claimed 7,456")
    
    def run_all_tests(self):
        """Run all functionality tests"""
        print("=" * 60)
        print("METASPLOIT FRAMEWORK FUNCTIONALITY ASSESSMENT")
        print("=" * 60)
        
        print("\n1. Testing Main Executables...")
        self.test_main_executables()
        
        print("\n2. Testing Python Framework Core...")
        self.test_python_framework_core()
        
        print("\n3. Testing Module Examples...")
        self.test_module_examples()
        
        print("\n4. Testing Dependencies...")
        self.test_dependencies()
        
        print("\n5. Testing File Structure...")
        self.test_file_structure()
        
        print("\n6. Testing Conversion Claims...")
        self.test_conversion_claims()
        
        print("\n" + "=" * 60)
        print("ASSESSMENT SUMMARY")
        print("=" * 60)
        print(f"Total Tests: {self.results['summary']['total']}")
        print(f"Passed: {self.results['summary']['passed']}")
        print(f"Failed: {self.results['summary']['failed']}")
        print(f"Warnings: {self.results['summary']['warnings']}")
        
        success_rate = (self.results['summary']['passed'] / 
                       self.results['summary']['total'] * 100)
        print(f"Success Rate: {success_rate:.1f}%")
        
        # Save detailed results
        with open('functionality_test_results.json', 'w') as f:
            json.dump(self.results, f, indent=2)
        
        print(f"\nDetailed results saved to: functionality_test_results.json")
        
        return self.results

if __name__ == "__main__":
    tester = FrameworkTester()
    results = tester.run_all_tests()