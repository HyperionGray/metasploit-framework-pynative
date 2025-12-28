#!/usr/bin/env python3
"""
Secure Command Execution Framework for Metasploit
Provides safe alternatives to exec() and system() calls with input validation
"""

import os
import sys
import subprocess
import shlex
import logging
import re
from typing import List, Dict, Optional, Union, Tuple
from pathlib import Path
import tempfile

class CommandExecutionError(Exception):
    """Custom exception for command execution errors"""
    pass

class SecureCommandExecutor:
    """
    Secure command execution with input validation and sandboxing
    """
    
    def __init__(self, allowed_commands=None, allowed_paths=None):
        self.allowed_commands = allowed_commands or [
            # Common safe commands for penetration testing
            'nmap', 'nc', 'netcat', 'curl', 'wget', 'ping', 'traceroute',
            'dig', 'nslookup', 'whois', 'ssh', 'scp', 'rsync',
            # MSF specific tools
            'msfconsole', 'msfvenom', 'msfd', 'msfdb',
            # Analysis tools
            'strings', 'file', 'hexdump', 'objdump', 'readelf',
            # Safe system commands
            'ls', 'cat', 'grep', 'awk', 'sed', 'sort', 'uniq', 'wc',
            'head', 'tail', 'find', 'locate', 'which', 'whereis'
        ]
        
        self.allowed_paths = allowed_paths or [
            '/usr/bin', '/bin', '/usr/local/bin',
            '/opt/metasploit-framework/bin',
            '/workspace/tools', '/workspace/scripts'
        ]
        
        self.dangerous_patterns = [
            r'[;&|`$()]',  # Command injection characters
            r'\.\./',      # Path traversal
            r'/etc/',      # System config access
            r'/proc/',     # Process info access
            r'rm\s+-rf',   # Dangerous deletion
            r'chmod\s+777', # Dangerous permissions
            r'sudo',       # Privilege escalation
            r'su\s+',      # User switching
        ]
        
        self.logger = logging.getLogger(__name__)
    
    def validate_command(self, command: str) -> bool:
        """
        Validate command for security issues
        Returns True if safe, False if dangerous
        """
        # Check for dangerous patterns
        for pattern in self.dangerous_patterns:
            if re.search(pattern, command, re.IGNORECASE):
                self.logger.warning(f"Dangerous pattern detected in command: {pattern}")
                return False
        
        # Parse command to check executable
        try:
            parsed_cmd = shlex.split(command)
            if not parsed_cmd:
                return False
            
            executable = parsed_cmd[0]
            
            # Check if command is in allowed list
            if executable not in self.allowed_commands:
                # Check if it's a full path to an allowed location
                if not any(executable.startswith(path) for path in self.allowed_paths):
                    self.logger.warning(f"Command not in allowed list: {executable}")
                    return False
        
        except ValueError as e:
            self.logger.error(f"Command parsing failed: {e}")
            return False
        
        return True
    
    def sanitize_arguments(self, args: List[str]) -> List[str]:
        """
        Sanitize command arguments
        """
        sanitized = []
        for arg in args:
            # Remove dangerous characters
            sanitized_arg = re.sub(r'[;&|`$()]', '', arg)
            # Prevent path traversal
            sanitized_arg = sanitized_arg.replace('../', '')
            sanitized.append(sanitized_arg)
        
        return sanitized
    
    def execute_command(self, command: Union[str, List[str]], 
                       cwd: Optional[str] = None,
                       env: Optional[Dict[str, str]] = None,
                       timeout: int = 30,
                       capture_output: bool = True) -> subprocess.CompletedProcess:
        """
        Safely execute a command with validation
        """
        # Convert string command to list
        if isinstance(command, str):
            if not self.validate_command(command):
                raise CommandExecutionError(f"Command failed security validation: {command}")
            cmd_list = shlex.split(command)
        else:
            cmd_list = command
        
        # Sanitize arguments
        cmd_list = self.sanitize_arguments(cmd_list)
        
        # Validate executable exists and is allowed
        executable = cmd_list[0]
        if not self.is_executable_allowed(executable):
            raise CommandExecutionError(f"Executable not allowed: {executable}")
        
        # Set up safe environment
        safe_env = os.environ.copy()
        if env:
            safe_env.update(env)
        
        # Remove dangerous environment variables
        dangerous_env_vars = ['LD_PRELOAD', 'LD_LIBRARY_PATH', 'PYTHONPATH']
        for var in dangerous_env_vars:
            safe_env.pop(var, None)
        
        try:
            self.logger.info(f"Executing command: {' '.join(cmd_list)}")
            
            result = subprocess.run(
                cmd_list,
                cwd=cwd,
                env=safe_env,
                timeout=timeout,
                capture_output=capture_output,
                text=True,
                check=False  # Don't raise on non-zero exit
            )
            
            self.logger.info(f"Command completed with exit code: {result.returncode}")
            return result
            
        except subprocess.TimeoutExpired:
            raise CommandExecutionError(f"Command timed out after {timeout} seconds")
        except Exception as e:
            raise CommandExecutionError(f"Command execution failed: {e}")
    
    def is_executable_allowed(self, executable: str) -> bool:
        """
        Check if executable is allowed to run
        """
        # Check allowed commands list
        if executable in self.allowed_commands:
            return True
        
        # Check if it's a full path in allowed directories
        if os.path.isabs(executable):
            return any(executable.startswith(path) for path in self.allowed_paths)
        
        # Check if executable exists in PATH and is in allowed location
        try:
            full_path = subprocess.run(['which', executable], 
                                     capture_output=True, text=True, check=False)
            if full_path.returncode == 0:
                exe_path = full_path.stdout.strip()
                return any(exe_path.startswith(path) for path in self.allowed_paths)
        except:
            pass
        
        return False
    
    def execute_script(self, script_path: str, 
                      interpreter: str = 'python3',
                      args: Optional[List[str]] = None,
                      **kwargs) -> subprocess.CompletedProcess:
        """
        Safely execute a script file
        """
        script_path = Path(script_path)
        
        if not script_path.exists():
            raise CommandExecutionError(f"Script file not found: {script_path}")
        
        if not script_path.is_file():
            raise CommandExecutionError(f"Path is not a file: {script_path}")
        
        # Build command
        cmd = [interpreter, str(script_path)]
        if args:
            cmd.extend(args)
        
        return self.execute_command(cmd, **kwargs)

class LegacyCommandCompatibility:
    """
    Compatibility layer for legacy exec() and system() calls
    """
    
    def __init__(self):
        self.executor = SecureCommandExecutor()
        self.logger = logging.getLogger(__name__)
    
    def safe_system_replacement(self, command: str) -> int:
        """
        Safe replacement for os.system() calls
        """
        self.logger.info(f"Executing system command with security validation: {command}")
        
        try:
            result = self.executor.execute_command(command, capture_output=False)
            return result.returncode
        except CommandExecutionError as e:
            self.logger.error(f"System command failed: {e}")
            return -1
    
    def safe_popen_replacement(self, command: str, mode: str = 'r') -> Optional[subprocess.Popen]:
        """
        Safe replacement for os.popen() calls
        """
        self.logger.info(f"Opening process with security validation: {command}")
        
        try:
            if not self.executor.validate_command(command):
                raise CommandExecutionError("Command failed validation")
            
            cmd_list = shlex.split(command)
            cmd_list = self.executor.sanitize_arguments(cmd_list)
            
            if 'w' in mode:
                return subprocess.Popen(cmd_list, stdin=subprocess.PIPE, text=True)
            else:
                return subprocess.Popen(cmd_list, stdout=subprocess.PIPE, text=True)
                
        except Exception as e:
            self.logger.error(f"Popen failed: {e}")
            return None
    
    def safe_exec_replacement(self, command: str, globals_dict=None, locals_dict=None):
        """
        Safe replacement for exec() calls that execute system commands
        """
        # If it looks like a system command, use command executor
        if any(cmd in command for cmd in ['os.system', 'subprocess.', 'popen']):
            return self.safe_system_replacement(command)
        else:
            # For Python code execution, use secure script executor
            from .secure_script_execution import secure_eval
            return secure_eval(command, globals_dict, locals_dict)

# Global instances
secure_command_executor = SecureCommandExecutor()
legacy_command_compatibility = LegacyCommandCompatibility()

def secure_system(command: str) -> int:
    """Drop-in replacement for os.system()"""
    return legacy_command_compatibility.safe_system_replacement(command)

def secure_popen(command: str, mode: str = 'r'):
    """Drop-in replacement for os.popen()"""
    return legacy_command_compatibility.safe_popen_replacement(command, mode)

def secure_exec_command(command: str, **kwargs):
    """Safe command execution with validation"""
    return secure_command_executor.execute_command(command, **kwargs)