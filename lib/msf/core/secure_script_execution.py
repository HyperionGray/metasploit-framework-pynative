#!/usr/bin/env python3
"""
Secure Script Execution Framework for Metasploit
Replaces dangerous eval() calls with safer alternatives
"""

import ast
import sys
import os
import logging
import types
import importlib.util
from pathlib import Path
from typing import Any, Dict, Optional, Union
import tempfile
import subprocess

class ScriptExecutionError(Exception):
    """Custom exception for script execution errors"""
    pass

class SecureScriptExecutor:
    """
    Secure replacement for eval() based script execution
    Provides sandboxed execution with input validation
    """
    
    def __init__(self, allowed_imports=None, allowed_builtins=None):
        self.allowed_imports = allowed_imports or [
            'os', 'sys', 'logging', 'json', 'base64', 'hashlib',
            'socket', 'struct', 'time', 'datetime', 'random',
            'msf', 'rex', 'metasploit'
        ]
        self.allowed_builtins = allowed_builtins or [
            'len', 'str', 'int', 'float', 'bool', 'list', 'dict',
            'tuple', 'set', 'range', 'enumerate', 'zip', 'map',
            'filter', 'sorted', 'min', 'max', 'sum', 'any', 'all',
            'print', 'isinstance', 'hasattr', 'getattr', 'setattr'
        ]
        self.logger = logging.getLogger(__name__)
    
    def validate_script_content(self, script_content: str) -> bool:
        """
        Validate script content for dangerous patterns
        Returns True if safe, False if dangerous
        """
        dangerous_patterns = [
            'eval(', 'exec(', 'compile(',
            '__import__', 'importlib',
            'subprocess.', 'os.system', 'os.popen',
            'open(', 'file(',
            'globals()', 'locals()', 'vars()',
            'setattr(', 'delattr(',
            '__builtins__', '__globals__'
        ]
        
        for pattern in dangerous_patterns:
            if pattern in script_content:
                self.logger.warning(f"Dangerous pattern detected: {pattern}")
                return False
        
        # Try to parse as valid Python
        try:
            ast.parse(script_content)
        except SyntaxError as e:
            self.logger.error(f"Script syntax error: {e}")
            return False
        
        return True
    
    def create_safe_globals(self, additional_globals=None) -> Dict[str, Any]:
        """Create a safe globals dictionary for script execution"""
        safe_globals = {
            '__builtins__': {
                name: getattr(__builtins__, name) 
                for name in self.allowed_builtins 
                if hasattr(__builtins__, name)
            }
        }
        
        # Add allowed modules
        for module_name in self.allowed_imports:
            try:
                safe_globals[module_name] = __import__(module_name)
            except ImportError:
                self.logger.warning(f"Could not import allowed module: {module_name}")
        
        # Add additional globals if provided
        if additional_globals:
            safe_globals.update(additional_globals)
        
        return safe_globals
    
    def execute_script_content(self, script_content: str, 
                             script_globals=None, 
                             script_locals=None) -> Any:
        """
        Safely execute script content with validation
        """
        if not self.validate_script_content(script_content):
            raise ScriptExecutionError("Script content failed security validation")
        
        # Create safe execution environment
        safe_globals = self.create_safe_globals(script_globals)
        safe_locals = script_locals or {}
        
        try:
            # Compile and execute
            compiled_code = compile(script_content, '<secure_script>', 'exec')
            exec(compiled_code, safe_globals, safe_locals)
            return safe_locals
        except Exception as e:
            self.logger.error(f"Script execution failed: {e}")
            raise ScriptExecutionError(f"Script execution failed: {e}")
    
    def execute_script_file(self, script_path: Union[str, Path], 
                          script_globals=None, 
                          script_locals=None) -> Any:
        """
        Safely execute a script file
        """
        script_path = Path(script_path)
        
        if not script_path.exists():
            raise ScriptExecutionError(f"Script file not found: {script_path}")
        
        if not script_path.is_file():
            raise ScriptExecutionError(f"Path is not a file: {script_path}")
        
        # Read script content
        try:
            with open(script_path, 'r', encoding='utf-8') as f:
                script_content = f.read()
        except Exception as e:
            raise ScriptExecutionError(f"Could not read script file: {e}")
        
        return self.execute_script_content(script_content, script_globals, script_locals)

class LegacyScriptCompatibility:
    """
    Compatibility layer for legacy Ruby script execution
    Provides safe alternatives to eval() for Ruby-to-Python migration
    """
    
    def __init__(self):
        self.executor = SecureScriptExecutor()
        self.logger = logging.getLogger(__name__)
    
    def safe_eval_replacement(self, code_string: str, binding_context=None):
        """
        Safe replacement for eval() calls in legacy code
        """
        self.logger.info("Executing legacy script with security validation")
        
        # Convert binding context to globals/locals
        script_globals = {}
        script_locals = {}
        
        if binding_context:
            # Extract variables from binding context if available
            if hasattr(binding_context, 'local_variables'):
                for var in binding_context.local_variables():
                    script_locals[var] = getattr(binding_context, var, None)
        
        return self.executor.execute_script_content(
            code_string, script_globals, script_locals
        )
    
    def safe_file_execution(self, file_path: str, binding_context=None):
        """
        Safe replacement for file-based eval() calls
        """
        self.logger.info(f"Executing script file with security validation: {file_path}")
        
        script_globals = {}
        script_locals = {}
        
        if binding_context:
            # Extract context variables
            if hasattr(binding_context, 'local_variables'):
                for var in binding_context.local_variables():
                    script_locals[var] = getattr(binding_context, var, None)
        
        return self.executor.execute_script_file(
            file_path, script_globals, script_locals
        )

# Global instances for easy access
secure_executor = SecureScriptExecutor()
legacy_compatibility = LegacyScriptCompatibility()

def secure_eval(code_string: str, globals_dict=None, locals_dict=None):
    """
    Drop-in replacement for eval() with security validation
    """
    return secure_executor.execute_script_content(
        code_string, globals_dict, locals_dict
    )

def secure_exec_file(file_path: str, globals_dict=None, locals_dict=None):
    """
    Drop-in replacement for file-based eval() with security validation
    """
    return secure_executor.execute_script_file(
        file_path, globals_dict, locals_dict
    )