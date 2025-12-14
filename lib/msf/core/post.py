#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Post-exploitation module base class
"""

from typing import Dict, Any, Optional
from .module import Module


class Post(Module):
    """
    Base class for all post-exploitation modules
    
    Post modules operate on existing sessions.
    """
    
    def __init__(self, info: Optional[Dict[str, Any]] = None):
        """
        Initialize post module
        
        Args:
            info: Module metadata
        """
        super().__init__(info)
        self.session = None
        
    def run(self):
        """
        Main run method - must be implemented by subclasses
        """
        raise NotImplementedError("Run method must be implemented")
        

class File:
    """
    File operations mixin for post modules
    """
    
    def read_file(self, path: str) -> bytes:
        """Read file from target"""
        pass
        
    def write_file(self, path: str, data: bytes):
        """Write file to target"""
        pass
        
    def file_exist(self, path: str) -> bool:
        """Check if file exists on target"""
        pass
