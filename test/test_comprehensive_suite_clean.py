#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
Comprehensive Test Suite - Refactored

This module now serves as a lightweight wrapper around the modular test suite.
The original comprehensive tests have been broken down into focused test modules
for better maintainability and organization.

Author: Metasploit Framework Python Migration Team
License: BSD-3-Clause
"""

import pytest
import sys
import os
from pathlib import Path

# Import the new test suite runner
from .test_suite_runner import TestSuiteRunner

# Import modular test modules
from . import (
    test_framework_core,
    test_network_protocols, 
    test_exploit_payload,
    test_e2e_playwright
)


class TestComprehensiveSuite:
    """Wrapper class that runs all modular test suites."""
    
    @pytest.mark.unit
    def test_run_all_unit_tests(self):
        """Run all unit tests from modular test suites."""
        runner = TestSuiteRunner()
        
        # Discover and run unit tests
        test_categories = runner.discover_tests()
        unit_tests = test_categories.get('unit', [])
        
        if unit_tests:
            result = runner.run_test_category('unit', unit_tests, coverage=False, verbose=False)
            assert result['status'] in ['passed', 'skipped'], f"Unit tests failed: {result}"
        else:
            pytest.skip("No unit tests found")
    
    @pytest.mark.integration
    def test_run_all_integration_tests(self):
        """Run all integration tests from modular test suites."""
        runner = TestSuiteRunner()
        
        # Discover and run integration tests
        test_categories = runner.discover_tests()
        integration_tests = test_categories.get('integration', [])
        
        if integration_tests:
            result = runner.run_test_category('integration', integration_tests, coverage=False, verbose=False)
            assert result['status'] in ['passed', 'skipped'], f"Integration tests failed: {result}"
        else:
            pytest.skip("No integration tests found")
    
    @pytest.mark.e2e
    def test_run_all_e2e_tests(self):
        """Run all E2E tests from modular test suites."""
        runner = TestSuiteRunner()
        
        # Discover and run E2E tests
        test_categories = runner.discover_tests()
        e2e_tests = test_categories.get('e2e', [])
        
        if e2e_tests:
            result = runner.run_test_category('e2e', e2e_tests, coverage=False, verbose=False)
            assert result['status'] in ['passed', 'skipped'], f"E2E tests failed: {result}"
        else:
            pytest.skip("No E2E tests found")


class TestLegacyCompatibility:
    """Tests to ensure backward compatibility with existing test infrastructure."""
    
    @pytest.mark.unit
    def test_legacy_test_discovery(self):
        """Test that legacy test patterns still work."""
        # Ensure old test discovery patterns still function
        test_dir = Path(__file__).parent
        
        # Find test files using old patterns
        legacy_test_files = list(test_dir.glob('test_*.py'))
        assert len(legacy_test_files) > 0, "Should find test files"
        
        # Verify new modular files exist
        expected_files = [
            'test_framework_core.py',
            'test_network_protocols.py', 
            'test_exploit_payload.py',
            'test_e2e_playwright.py',
            'test_suite_runner.py'
        ]
        
        for expected_file in expected_files:
            file_path = test_dir / expected_file
            assert file_path.exists(), f"Expected test file {expected_file} should exist"
    
    @pytest.mark.unit
    def test_pytest_markers_work(self):
        """Test that pytest markers are properly configured."""
        # Test that we can use pytest markers
        assert hasattr(pytest.mark, 'unit'), "unit marker should be available"
        assert hasattr(pytest.mark, 'integration'), "integration marker should be available"
        assert hasattr(pytest.mark, 'e2e'), "e2e marker should be available"


def run_comprehensive_tests():
    """
    Legacy function to run comprehensive tests.
    Now delegates to the new modular test runner.
    """
    print("🔄 Running comprehensive test suite (refactored)...")
    
    runner = TestSuiteRunner()
    summary = runner.run_all_tests(
        categories=['unit', 'integration', 'e2e'],
        coverage=True,
        verbose=True
    )
    
    runner.print_summary(summary)
    
    # Return success/failure
    all_passed = all(result['status'] == 'passed' 
                    for result in summary['categories'].values())
    return all_passed


if __name__ == '__main__':
    # Run comprehensive tests with verbose output
    success = run_comprehensive_tests()
    sys.exit(0 if success else 1)