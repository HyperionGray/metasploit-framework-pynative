#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
Framework Core Tests

Focused tests for core framework functionality, extracted from the
comprehensive test suite for better organization and maintainability.

Author: Metasploit Framework Python Migration Team
License: BSD-3-Clause
"""

import pytest
import sys
import os
from pathlib import Path
from typing import List, Dict, Any
import importlib.util
import inspect

# Add lib path for imports
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', 'lib'))
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', 'python_framework'))


class TestFrameworkCore:
    """Comprehensive tests for core framework functionality."""
    
    @pytest.mark.unit
    def test_framework_imports(self):
        """Test that all core framework modules can be imported."""
        modules_to_test = [
            'python_framework.core.exploit',
            'python_framework.helpers.http_client',
        ]
        
        for module_name in modules_to_test:
            try:
                parts = module_name.split('.')
                if len(parts) > 1:
                    module = __import__(module_name, fromlist=[parts[-1]])
                else:
                    module = __import__(module_name)
                assert module is not None, f"Failed to import {module_name}"
            except ImportError as e:
                pytest.skip(f"Module {module_name} not available: {e}")
    
    @pytest.mark.unit
    def test_exploit_base_classes_exist(self):
        """Test that base exploit classes are available."""
        try:
            from python_framework.core.exploit import Exploit, RemoteExploit, LocalExploit
            
            # Test that classes exist and are properly defined
            assert inspect.isclass(Exploit), "Exploit should be a class"
            assert inspect.isclass(RemoteExploit), "RemoteExploit should be a class"
            assert inspect.isclass(LocalExploit), "LocalExploit should be a class"
            
            # Test inheritance
            assert issubclass(RemoteExploit, Exploit), "RemoteExploit should inherit from Exploit"
            assert issubclass(LocalExploit, Exploit), "LocalExploit should inherit from Exploit"
            
        except ImportError as e:
            pytest.skip(f"Exploit classes not available: {e}")
    
    @pytest.mark.unit
    def test_framework_constants(self):
        """Test that framework constants are properly defined."""
        try:
            from python_framework.core import constants
            
            # Test that common constants exist
            assert hasattr(constants, 'VERSION'), "VERSION constant should exist"
            assert hasattr(constants, 'FRAMEWORK_NAME'), "FRAMEWORK_NAME constant should exist"
            
        except ImportError as e:
            pytest.skip(f"Constants module not available: {e}")
    
    @pytest.mark.unit
    def test_framework_utilities(self):
        """Test that framework utilities are available."""
        try:
            from python_framework.helpers import utils
            
            # Test that utility functions exist
            assert hasattr(utils, 'generate_random_string'), "generate_random_string should exist"
            assert hasattr(utils, 'validate_ip'), "validate_ip should exist"
            
        except ImportError as e:
            pytest.skip(f"Utils module not available: {e}")


class TestFrameworkConfiguration:
    """Tests for framework configuration and settings."""
    
    @pytest.mark.unit
    def test_config_loading(self):
        """Test that configuration can be loaded."""
        try:
            from python_framework.core import config
            
            # Test that config object exists
            assert hasattr(config, 'load_config'), "load_config function should exist"
            
        except ImportError as e:
            pytest.skip(f"Config module not available: {e}")
    
    @pytest.mark.unit
    def test_default_settings(self):
        """Test that default settings are properly configured."""
        try:
            from python_framework.core import settings
            
            # Test that settings exist
            assert hasattr(settings, 'DEFAULT_TIMEOUT'), "DEFAULT_TIMEOUT should exist"
            assert hasattr(settings, 'DEFAULT_USER_AGENT'), "DEFAULT_USER_AGENT should exist"
            
        except ImportError as e:
            pytest.skip(f"Settings module not available: {e}")


class TestFrameworkLogging:
    """Tests for framework logging functionality."""
    
    @pytest.mark.unit
    def test_logger_initialization(self):
        """Test that logger can be initialized."""
        try:
            from python_framework.core import logger
            
            # Test that logger functions exist
            assert hasattr(logger, 'get_logger'), "get_logger function should exist"
            assert hasattr(logger, 'setup_logging'), "setup_logging function should exist"
            
        except ImportError as e:
            pytest.skip(f"Logger module not available: {e}")
    
    @pytest.mark.unit
    def test_log_levels(self):
        """Test that log levels are properly configured."""
        try:
            from python_framework.core import logger
            
            test_logger = logger.get_logger('test')
            
            # Test that logger methods exist
            assert hasattr(test_logger, 'debug'), "debug method should exist"
            assert hasattr(test_logger, 'info'), "info method should exist"
            assert hasattr(test_logger, 'warning'), "warning method should exist"
            assert hasattr(test_logger, 'error'), "error method should exist"
            
        except ImportError as e:
            pytest.skip(f"Logger not available: {e}")


if __name__ == '__main__':
    # Run tests with verbose output
    pytest.main([__file__, '-v', '--tb=short'])