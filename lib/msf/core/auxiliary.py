#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Auxiliary module base class
"""

from typing import Dict, Any, Optional
from .module import Module


class Auxiliary(Module):
    """
    Base class for all auxiliary modules
    
    Auxiliary modules are used for scanning, fuzzing, and other
    non-exploit operations.
    """
    
    def __init__(self, info: Optional[Dict[str, Any]] = None):
        """
        Initialize auxiliary module
        
        Args:
            info: Module metadata
        """
        super().__init__(info)
        
    def run(self):
        """
        Main run method - must be implemented by subclasses
        """
        raise NotImplementedError("Run method must be implemented")
        
    def cleanup(self):
        """
        Cleanup after module execution
        """
        pass
