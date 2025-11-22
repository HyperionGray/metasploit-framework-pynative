#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
MSF Core Integrations Module

This module provides base classes and utilities for integrating external
tools and frameworks into Metasploit PyNative.
"""

__version__ = '1.0.0'
__all__ = ['BaseIntegration', 'IntegrationRegistry']


class IntegrationRegistry:
    """Registry for managing external tool integrations."""
    
    _integrations = {}
    
    @classmethod
    def register(cls, name, integration_class):
        """Register an integration by name."""
        cls._integrations[name] = integration_class
    
    @classmethod
    def get(cls, name):
        """Get an integration by name."""
        return cls._integrations.get(name)
    
    @classmethod
    def list_all(cls):
        """List all registered integrations."""
        return list(cls._integrations.keys())


class BaseIntegration:
    """
    Base class for external tool integrations.
    
    All integration modules should inherit from this class and implement
    the required methods.
    """
    
    def __init__(self, config=None):
        """
        Initialize the integration.
        
        Args:
            config (dict): Configuration dictionary for the integration
        """
        self.config = config or {}
        self.name = self.__class__.__name__
        self.enabled = False
        
    def check_dependencies(self):
        """
        Check if all dependencies for this integration are available.
        
        Returns:
            tuple: (bool, list) - (success, missing_dependencies)
        """
        raise NotImplementedError("Subclasses must implement check_dependencies()")
    
    def initialize(self):
        """
        Initialize the integration.
        
        Returns:
            bool: True if initialization succeeded, False otherwise
        """
        raise NotImplementedError("Subclasses must implement initialize()")
    
    def execute(self, *args, **kwargs):
        """
        Execute the main functionality of the integration.
        
        Returns:
            dict: Results dictionary with status and data
        """
        raise NotImplementedError("Subclasses must implement execute()")
    
    def cleanup(self):
        """Clean up resources used by the integration."""
        pass
    
    def get_info(self):
        """
        Get information about this integration.
        
        Returns:
            dict: Information dictionary
        """
        return {
            'name': self.name,
            'enabled': self.enabled,
            'config': self.config
        }
