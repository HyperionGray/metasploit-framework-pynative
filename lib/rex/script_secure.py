#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
Secure Script Execution Module for Rex Framework
Replaces the dangerous eval() based script execution with secure alternatives
"""

import logging
import sys
import os
from pathlib import Path

# Add lib path for imports
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '../../'))

from msf.core.secure_script_execution import SecureScriptExecutor, ScriptExecutionError

class ScriptCompleted(Exception):
    """Exception to signal script completion"""
    pass

class SecureScript:
    """
    Secure replacement for Rex::Script module
    Provides safe script execution without eval()
    """
    
    def __init__(self):
        self.executor = SecureScriptExecutor()
        self.logger = logging.getLogger(__name__)
    
    def execute_file(self, file_path, binding_context=None):
        """
        Secure replacement for execute_file method
        Reads and executes a script file safely
        """
        try:
            file_path = Path(file_path)
            
            if not file_path.exists():
                raise ScriptExecutionError(f"Script file not found: {file_path}")
            
            # Read file content
            with open(file_path, 'r', encoding='utf-8') as f:
                script_content = f.read()
            
            return self.execute(script_content, binding_context)
            
        except ScriptCompleted:
            # Normal completion
            pass
        except Exception as e:
            self.logger.error(f"Script execution failed: {e}")
            raise
    
    def execute(self, script_content, binding_context=None):
        """
        Secure replacement for execute method
        Executes script content safely without eval()
        """
        try:
            # Prepare execution context
            script_globals = {}
            script_locals = {}
            
            # Add binding context if provided
            if binding_context:
                if hasattr(binding_context, '__dict__'):
                    script_locals.update(binding_context.__dict__)
            
            # Add completion function to locals
            script_locals['completed'] = self._script_completed
            
            # Execute with security validation
            result = self.executor.execute_script_content(
                script_content, script_globals, script_locals
            )
            
            return result
            
        except ScriptCompleted:
            # Normal completion
            pass
        except Exception as e:
            self.logger.error(f"Script execution failed: {e}")
            raise
    
    def _script_completed(self):
        """Function to signal script completion"""
        raise ScriptCompleted()

# Global instance for compatibility
secure_script = SecureScript()

# Compatibility functions
def execute_file(file_path, binding_context=None):
    """Global function for file execution"""
    return secure_script.execute_file(file_path, binding_context)

def execute(script_content, binding_context=None):
    """Global function for script execution"""
    return secure_script.execute(script_content, binding_context)