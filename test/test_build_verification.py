#!/usr/bin/env python3
"""
Build Verification Tests

Simple tests to verify that the build system is working correctly
and all basic components can be imported and initialized.
"""

import pytest
import sys
import os
from pathlib import Path

# Add lib path for imports
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', 'lib'))


class TestBuildVerification:
    """Test basic build and import functionality."""
    
    @pytest.mark.unit
    def test_python_version(self):
        """Test that we're running on a supported Python version."""
        assert sys.version_info >= (3, 9), f"Python 3.9+ required, got {sys.version_info}"
    
    @pytest.mark.unit
    def test_basic_imports(self):
        """Test that basic Python modules can be imported."""
        import json
        import urllib.request
        import hashlib
        import base64
        assert True  # If we get here, imports worked
    
    @pytest.mark.unit
    def test_test_framework_imports(self):
        """Test that testing framework components can be imported."""
        import pytest
        assert pytest.__version__ is not None
    
    @pytest.mark.unit
    def test_project_structure(self):
        """Test that basic project structure exists."""
        project_root = Path(__file__).parent.parent
        
        # Check for essential directories
        assert (project_root / "lib").exists(), "lib directory missing"
        assert (project_root / "modules").exists(), "modules directory missing"
        assert (project_root / "test").exists(), "test directory missing"
        
        # Check for essential files
        assert (project_root / "requirements.txt").exists(), "requirements.txt missing"
        assert (project_root / "pyproject.toml").exists(), "pyproject.toml missing"
        assert (project_root / "README.md").exists(), "README.md missing"
    
    @pytest.mark.unit
    def test_run_tests_script_exists(self):
        """Test that the run_tests.py script exists and is executable."""
        project_root = Path(__file__).parent.parent
        run_tests_script = project_root / "run_tests.py"
        
        assert run_tests_script.exists(), "run_tests.py script missing"
        assert run_tests_script.is_file(), "run_tests.py is not a file"
        
        # Check if it's readable
        with open(run_tests_script, 'r') as f:
            content = f.read()
            assert "TestRunner" in content, "TestRunner class not found in run_tests.py"
    
    @pytest.mark.integration
    def test_requirements_installable(self):
        """Test that requirements.txt is properly formatted."""
        project_root = Path(__file__).parent.parent
        requirements_file = project_root / "requirements.txt"
        
        with open(requirements_file, 'r') as f:
            lines = f.readlines()
        
        # Check for basic structure
        assert len(lines) > 0, "requirements.txt is empty"
        
        # Check that there are no obvious duplicate entries
        package_names = []
        for line in lines:
            line = line.strip()
            if line and not line.startswith('#'):
                if '>=' in line:
                    package_name = line.split('>=')[0].strip()
                    package_names.append(package_name)
        
        # Check for duplicates
        duplicates = [pkg for pkg in set(package_names) if package_names.count(pkg) > 1]
        assert len(duplicates) == 0, f"Duplicate packages found in requirements.txt: {duplicates}"
    
    @pytest.mark.unit
    def test_pytest_configuration(self):
        """Test that pytest configuration is valid."""
        project_root = Path(__file__).parent.parent
        pyproject_file = project_root / "pyproject.toml"
        
        with open(pyproject_file, 'r') as f:
            content = f.read()
        
        # Check for pytest configuration
        assert "[tool.pytest.ini_options]" in content, "pytest configuration missing"
        assert "testpaths" in content, "testpaths not configured"
        assert "markers" in content, "test markers not configured"


class TestFrameworkMarkers:
    """Test that all required pytest markers are properly configured."""
    
    @pytest.mark.unit
    def test_unit_marker(self):
        """Test unit marker functionality."""
        assert True
    
    @pytest.mark.integration
    def test_integration_marker(self):
        """Test integration marker functionality."""
        assert True
    
    @pytest.mark.security
    def test_security_marker(self):
        """Test security marker functionality."""
        assert True
    
    @pytest.mark.performance
    def test_performance_marker(self):
        """Test performance marker functionality."""
        assert True
    
    @pytest.mark.exploit
    def test_exploit_marker(self):
        """Test exploit marker functionality."""
        assert True
    
    @pytest.mark.ruby_compat
    def test_ruby_compat_marker(self):
        """Test Ruby compatibility marker functionality."""
        assert True


if __name__ == "__main__":
    # Run basic verification tests
    pytest.main([__file__, "-v"])