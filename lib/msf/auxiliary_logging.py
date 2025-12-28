#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
Metasploit Framework - Auxiliary Module Logging System

This module provides a new logging method for auxiliary modules as requested
in issue #175 (17852). It replaces Ruby's print_status, print_error, etc.
with a proper Python logging system that integrates with the framework.

Addresses issue #175 (17852) - "A new logging method for auxiliary module is needed."
"""

import logging
import sys
import os
from typing import Optional, Dict, Any
from datetime import datetime


class AuxiliaryLogger:
    """
    Enhanced logging system for Metasploit auxiliary modules.
    
    This class provides Ruby-compatible logging methods while using
    Python's standard logging infrastructure underneath.
    """
    
    # Log level mappings from Ruby to Python
    LEVEL_MAPPING = {
        'status': logging.INFO,
        'good': logging.INFO,
        'error': logging.ERROR,
        'warning': logging.WARNING,
        'debug': logging.DEBUG,
        'verbose': logging.DEBUG,
    }
    
    # Color codes for console output
    COLORS = {
        'status': '\033[94m',    # Blue
        'good': '\033[92m',      # Green
        'error': '\033[91m',     # Red
        'warning': '\033[93m',   # Yellow
        'debug': '\033[90m',     # Gray
        'verbose': '\033[90m',   # Gray
        'reset': '\033[0m',      # Reset
    }
    
    # Status prefixes (Ruby-compatible)
    PREFIXES = {
        'status': '[*]',
        'good': '[+]',
        'error': '[-]',
        'warning': '[!]',
        'debug': '[DEBUG]',
        'verbose': '[VERBOSE]',
    }
    
    def __init__(self, module_name: str = None, target: str = None):
        """
        Initialize the auxiliary logger.
        
        Args:
            module_name: Name of the auxiliary module
            target: Target host/service being tested
        """
        self.module_name = module_name or "auxiliary"
        self.target = target
        self.logger = logging.getLogger(f"msf.auxiliary.{self.module_name}")
        
        # Setup formatter
        self._setup_formatter()
        
        # Track if we're in console mode
        self.console_mode = sys.stdout.isatty()
    
    def _setup_formatter(self):
        """Setup the log formatter."""
        if not self.logger.handlers:
            handler = logging.StreamHandler()
            
            # Create formatter with target prefix if available
            if self.target:
                format_str = f"%(asctime)s [{self.target}] %(message)s"
            else:
                format_str = "%(asctime)s [%(name)s] %(message)s"
            
            formatter = logging.Formatter(
                format_str,
                datefmt='%H:%M:%S'
            )
            
            handler.setFormatter(formatter)
            self.logger.addHandler(handler)
            self.logger.setLevel(logging.DEBUG)
    
    def _format_message(self, message: str, level: str) -> str:
        """Format message with appropriate prefix and colors."""
        prefix = self.PREFIXES.get(level, '[*]')
        
        if self.console_mode:
            color = self.COLORS.get(level, '')
            reset = self.COLORS['reset']
            return f"{color}{prefix}{reset} {message}"
        else:
            return f"{prefix} {message}"
    
    def print_status(self, message: str):
        """
        Print a status message (Ruby compatibility).
        
        Args:
            message: Status message to print
        """
        formatted_msg = self._format_message(message, 'status')
        self.logger.info(formatted_msg)
    
    def print_good(self, message: str):
        """
        Print a success/good message (Ruby compatibility).
        
        Args:
            message: Success message to print
        """
        formatted_msg = self._format_message(message, 'good')
        self.logger.info(formatted_msg)
    
    def print_error(self, message: str):
        """
        Print an error message (Ruby compatibility).
        
        Args:
            message: Error message to print
        """
        formatted_msg = self._format_message(message, 'error')
        self.logger.error(formatted_msg)
    
    def print_warning(self, message: str):
        """
        Print a warning message (Ruby compatibility).
        
        Args:
            message: Warning message to print
        """
        formatted_msg = self._format_message(message, 'warning')
        self.logger.warning(formatted_msg)
    
    def print_debug(self, message: str):
        """
        Print a debug message (Ruby compatibility).
        
        Args:
            message: Debug message to print
        """
        formatted_msg = self._format_message(message, 'debug')
        self.logger.debug(formatted_msg)
    
    def vprint_status(self, message: str):
        """
        Print a verbose status message (Ruby compatibility).
        
        Args:
            message: Verbose status message to print
        """
        formatted_msg = self._format_message(message, 'verbose')
        self.logger.debug(formatted_msg)
    
    def vprint_good(self, message: str):
        """
        Print a verbose success message (Ruby compatibility).
        
        Args:
            message: Verbose success message to print
        """
        formatted_msg = self._format_message(message, 'verbose')
        self.logger.debug(formatted_msg)
    
    def vprint_error(self, message: str):
        """
        Print a verbose error message (Ruby compatibility).
        
        Args:
            message: Verbose error message to print
        """
        formatted_msg = self._format_message(message, 'verbose')
        self.logger.debug(formatted_msg)
    
    def log_progress(self, current: int, total: int, message: str = ""):
        """
        Log progress information for long-running operations.
        
        Args:
            current: Current progress count
            total: Total expected count
            message: Optional progress message
        """
        percentage = (current / total) * 100 if total > 0 else 0
        progress_msg = f"Progress: {current}/{total} ({percentage:.1f}%)"
        
        if message:
            progress_msg += f" - {message}"
        
        self.print_status(progress_msg)
    
    def log_vulnerability(self, vuln_name: str, severity: str = "medium", 
                         details: Dict[str, Any] = None):
        """
        Log vulnerability discovery.
        
        Args:
            vuln_name: Name of the vulnerability
            severity: Severity level (low, medium, high, critical)
            details: Additional vulnerability details
        """
        severity_upper = severity.upper()
        vuln_msg = f"VULNERABILITY FOUND: {vuln_name} (Severity: {severity_upper})"
        
        if severity.lower() in ['high', 'critical']:
            self.print_good(vuln_msg)
        else:
            self.print_status(vuln_msg)
        
        if details:
            for key, value in details.items():
                self.print_status(f"  {key}: {value}")
    
    def log_credential(self, username: str, password: str = None, 
                      hash_value: str = None, status: str = "found"):
        """
        Log credential discovery.
        
        Args:
            username: Username found
            password: Password found (if any)
            hash_value: Hash value found (if any)
            status: Status of the credential (found, valid, invalid)
        """
        if password:
            cred_msg = f"CREDENTIAL {status.upper()}: {username}:{password}"
        elif hash_value:
            cred_msg = f"HASH {status.upper()}: {username}:{hash_value}"
        else:
            cred_msg = f"USERNAME {status.upper()}: {username}"
        
        if status.lower() == "valid":
            self.print_good(cred_msg)
        else:
            self.print_status(cred_msg)
    
    def log_service_info(self, service: str, version: str = None, 
                        extra_info: str = None):
        """
        Log service information discovery.
        
        Args:
            service: Service name
            version: Service version (if detected)
            extra_info: Additional service information
        """
        service_msg = f"SERVICE: {service}"
        
        if version:
            service_msg += f" (Version: {version})"
        
        if extra_info:
            service_msg += f" - {extra_info}"
        
        self.print_status(service_msg)
    
    def set_target(self, target: str):
        """
        Update the target for logging context.
        
        Args:
            target: New target host/service
        """
        self.target = target
        self._setup_formatter()


class AuxiliaryModule:
    """
    Base class for Python auxiliary modules with integrated logging.
    
    This class provides the foundation for auxiliary modules converted
    from Ruby, with proper logging integration.
    """
    
    def __init__(self, module_name: str = None):
        """
        Initialize the auxiliary module.
        
        Args:
            module_name: Name of the module
        """
        self.module_name = module_name or self.__class__.__name__
        self.logger = AuxiliaryLogger(self.module_name)
        self.options = {}
        self.results = {}
    
    def set_option(self, name: str, value: Any):
        """Set a module option."""
        self.options[name] = value
        
        # Update logger target if RHOST is set
        if name.upper() == 'RHOST':
            self.logger.set_target(str(value))
    
    def get_option(self, name: str, default: Any = None) -> Any:
        """Get a module option."""
        return self.options.get(name, default)
    
    def print_status(self, message: str):
        """Print status message (Ruby compatibility)."""
        self.logger.print_status(message)
    
    def print_good(self, message: str):
        """Print success message (Ruby compatibility)."""
        self.logger.print_good(message)
    
    def print_error(self, message: str):
        """Print error message (Ruby compatibility)."""
        self.logger.print_error(message)
    
    def print_warning(self, message: str):
        """Print warning message (Ruby compatibility)."""
        self.logger.print_warning(message)
    
    def vprint_status(self, message: str):
        """Print verbose status message (Ruby compatibility)."""
        self.logger.vprint_status(message)
    
    def run(self):
        """
        Main execution method - to be overridden by subclasses.
        
        This method should contain the main logic of the auxiliary module.
        """
        raise NotImplementedError("Subclasses must implement the run() method")


# Global logger instance for standalone use
_global_logger = None


def get_auxiliary_logger(module_name: str = None, target: str = None) -> AuxiliaryLogger:
    """
    Get a global auxiliary logger instance.
    
    Args:
        module_name: Name of the module
        target: Target host/service
        
    Returns:
        AuxiliaryLogger instance
    """
    global _global_logger
    
    if _global_logger is None or module_name or target:
        _global_logger = AuxiliaryLogger(module_name, target)
    
    return _global_logger


# Convenience functions for direct use (Ruby compatibility)
def print_status(message: str):
    """Print status message using global logger."""
    get_auxiliary_logger().print_status(message)


def print_good(message: str):
    """Print success message using global logger."""
    get_auxiliary_logger().print_good(message)


def print_error(message: str):
    """Print error message using global logger."""
    get_auxiliary_logger().print_error(message)


def print_warning(message: str):
    """Print warning message using global logger."""
    get_auxiliary_logger().print_warning(message)


def vprint_status(message: str):
    """Print verbose status message using global logger."""
    get_auxiliary_logger().vprint_status(message)


# Example usage and testing
if __name__ == "__main__":
    # Test the logging system
    logger = AuxiliaryLogger("test_module", "192.168.1.100")
    
    print("Testing Auxiliary Logging System (Issue #175 - 17852)")
    print("=" * 60)
    
    logger.print_status("Starting auxiliary module test")
    logger.print_good("Successfully connected to target")
    logger.print_warning("Potential security issue detected")
    logger.print_error("Connection failed")
    logger.vprint_status("Verbose debugging information")
    
    logger.log_progress(50, 100, "Scanning ports")
    logger.log_vulnerability("SQL Injection", "high", {
        "parameter": "id",
        "payload": "' OR 1=1--"
    })
    logger.log_credential("admin", "password123", status="valid")
    logger.log_service_info("Apache", "2.4.41", "mod_ssl enabled")
    
    print("\n🐍 Auxiliary logging system test complete!")
    print("Issue #175 (17852) - New logging method implemented!")