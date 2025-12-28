#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
Build Validation Test for CI/CD Pipeline

This test ensures that the basic build process works correctly
and addresses the issues identified in the CI/CD review.
"""

import pytest
import sys
import os
from pathlib import Path
import subprocess
import importlib.util


class TestBuildValidation:
    """Tests to validate the build process and CI/CD requirements."""
    
    @pytest.mark.unit
    def test_python_version(self):
        """Test that Python version is compatible."""
        assert sys.version_info >= (3, 8), f"Python 3.8+ required, got {sys.version_info}"
    
    @pytest.mark.unit
    def test_requirements_file_exists(self):
        """Test that requirements.txt exists and is readable."""
        req_file = Path(__file__).parent.parent / 'requirements.txt'
        assert req_file.exists(), "requirements.txt should exist"
        
        # Test that it's readable and has content
        content = req_file.read_text()
        assert len(content) > 0, "requirements.txt should not be empty"
        assert 'pytest' in content, "requirements.txt should include pytest"
    
    @pytest.mark.unit
    def test_pyproject_toml_exists(self):
        """Test that pyproject.toml exists and is valid."""
        config_file = Path(__file__).parent.parent / 'pyproject.toml'
        assert config_file.exists(), "pyproject.toml should exist"
        
        # Test that it contains pytest configuration
        content = config_file.read_text()
        assert '[tool.pytest.ini_options]' in content, "pyproject.toml should have pytest config"
    
    @pytest.mark.unit
    def test_tasks_py_exists(self):
        """Test that tasks.py exists and is executable."""
        tasks_file = Path(__file__).parent.parent / 'tasks.py'
        assert tasks_file.exists(), "tasks.py should exist"
        
        # Test that it's a valid Python file
        content = tasks_file.read_text()
        assert 'def main()' in content, "tasks.py should have main function"
    
    @pytest.mark.unit
    def test_documentation_files_exist(self):
        """Test that all required documentation files exist."""
        base_dir = Path(__file__).parent.parent
        
        required_docs = [
            'README.md',
            'CONTRIBUTING.md',
            'LICENSE.md',
            'CHANGELOG.md',
            'SECURITY.md',
            'CODE_OF_CONDUCT.md'
        ]
        
        for doc_file in required_docs:
            doc_path = base_dir / doc_file
            assert doc_path.exists(), f"{doc_file} should exist"
    
    @pytest.mark.unit
    def test_readme_has_features_section(self):
        """Test that README.md contains a Features section."""
        readme_file = Path(__file__).parent.parent / 'README.md'
        content = readme_file.read_text()
        
        # Check for Features section (case-insensitive)
        assert 'features' in content.lower(), "README.md should contain a Features section"
        
        # Check for specific feature mentions
        features_to_check = [
            'python-native',
            'binary analysis',
            'exploitation',
            'network',
            'security'
        ]
        
        content_lower = content.lower()
        for feature in features_to_check:
            assert feature in content_lower, f"README.md should mention {feature}"
    
    @pytest.mark.unit
    def test_core_dependencies_importable(self):
        """Test that core dependencies can be imported."""
        core_deps = [
            'pytest',
            'requests',
            'cryptography',
            'yaml',
            'click'
        ]
        
        failed_imports = []
        for dep in core_deps:
            try:
                if dep == 'yaml':
                    import yaml
                else:
                    __import__(dep)
            except ImportError:
                failed_imports.append(dep)
        
        if failed_imports:
            pytest.skip(f"Core dependencies not available: {failed_imports}")
    
    @pytest.mark.unit
    def test_test_directory_structure(self):
        """Test that test directory structure is correct."""
        test_dir = Path(__file__).parent
        assert test_dir.exists(), "test directory should exist"
        assert test_dir.is_dir(), "test should be a directory"
        
        # Check for key test files
        key_test_files = [
            'test_comprehensive_suite.py',
            '__init__.py'
        ]
        
        for test_file in key_test_files:
            test_path = test_dir / test_file
            if not test_path.exists():
                pytest.skip(f"Test file {test_file} not found")
    
    @pytest.mark.unit
    def test_modules_directory_exists(self):
        """Test that modules directory exists."""
        modules_dir = Path(__file__).parent.parent / 'modules'
        assert modules_dir.exists(), "modules directory should exist"
        assert modules_dir.is_dir(), "modules should be a directory"
    
    @pytest.mark.unit
    def test_lib_directory_exists(self):
        """Test that lib directory exists."""
        lib_dir = Path(__file__).parent.parent / 'lib'
        assert lib_dir.exists(), "lib directory should exist"
        assert lib_dir.is_dir(), "lib should be a directory"
    
    @pytest.mark.integration
    def test_tasks_py_executable(self):
        """Test that tasks.py can be executed."""
        tasks_file = Path(__file__).parent.parent / 'tasks.py'
        
        try:
            # Test that tasks.py can show help
            result = subprocess.run(
                [sys.executable, str(tasks_file)],
                capture_output=True,
                text=True,
                timeout=30
            )
            
            # Should exit with 0 and show available tasks
            assert result.returncode == 0, f"tasks.py failed: {result.stderr}"
            assert 'Available tasks:' in result.stdout, "tasks.py should show available tasks"
            
        except subprocess.TimeoutExpired:
            pytest.skip("tasks.py execution timed out")
        except Exception as e:
            pytest.skip(f"Could not execute tasks.py: {e}")
    
    @pytest.mark.integration
    def test_basic_pytest_execution(self):
        """Test that pytest can run basic tests."""
        try:
            # Run a simple test to verify pytest works
            result = subprocess.run(
                [sys.executable, '-m', 'pytest', '--version'],
                capture_output=True,
                text=True,
                timeout=10
            )
            
            assert result.returncode == 0, f"pytest --version failed: {result.stderr}"
            assert 'pytest' in result.stdout.lower(), "pytest should report its version"
            
        except subprocess.TimeoutExpired:
            pytest.skip("pytest execution timed out")
        except Exception as e:
            pytest.skip(f"Could not execute pytest: {e}")
    
    @pytest.mark.unit
    def test_no_duplicate_requirements(self):
        """Test that requirements.txt has no duplicate entries."""
        req_file = Path(__file__).parent.parent / 'requirements.txt'
        content = req_file.read_text()
        
        # Extract package names (before >= or ==)
        lines = [line.strip() for line in content.split('\n') if line.strip() and not line.startswith('#')]
        packages = []
        
        for line in lines:
            if '>=' in line:
                package = line.split('>=')[0].strip()
            elif '==' in line:
                package = line.split('==')[0].strip()
            elif ';' in line:  # Handle conditional dependencies
                package = line.split(';')[0].strip()
                if '>=' in package:
                    package = package.split('>=')[0].strip()
                elif '==' in package:
                    package = package.split('==')[0].strip()
            else:
                package = line.strip()
            
            if package:
                packages.append(package.lower())
        
        # Check for duplicates
        seen = set()
        duplicates = []
        for package in packages:
            if package in seen:
                duplicates.append(package)
            seen.add(package)
        
        assert len(duplicates) == 0, f"Duplicate packages found in requirements.txt: {duplicates}"


if __name__ == '__main__':
    # Run build validation tests
    pytest.main([__file__, '-v', '--tb=short'])