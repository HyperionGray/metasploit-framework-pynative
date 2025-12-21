#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Module option classes
"""

from typing import Any, Optional, List


class Option:
    """Base option class"""
    
    def __init__(self, name: str, required: bool = False, default: Any = None, 
                 description: str = '', advanced: bool = False):
        """
        Initialize option
        
        Args:
            name: Option name
            required: Whether option is required
            default: Default value
            description: Option description
            advanced: Whether this is an advanced option
        """
        self.name = name
        self.required = required
        self.default = default
        self.description = description
        self.advanced = advanced
        
    def validate(self, value: Any) -> bool:
        """Validate option value"""
        if self.required and value is None:
            return False
        return True


class OptString(Option):
    """String option"""
    pass


class OptInt(Option):
    """Integer option"""
    
    def validate(self, value: Any) -> bool:
        """Validate integer value"""
        if not super().validate(value):
            return False
        if value is not None:
            try:
                int(value)
                return True
            except (ValueError, TypeError):
                return False
        return True


class OptPort(OptInt):
    """Port number option"""
    
    def validate(self, value: Any) -> bool:
        """Validate port number"""
        if not super().validate(value):
            return False
        if value is not None:
            try:
                port = int(value)
                return 0 <= port <= 65535
            except (ValueError, TypeError):
                return False
        return True


class OptBool(Option):
    """Boolean option"""
    
    def validate(self, value: Any) -> bool:
        """Validate boolean value"""
        if not super().validate(value):
            return False
        if value is not None:
            return isinstance(value, bool) or value in ['true', 'false', 'yes', 'no', '1', '0']
        return True


class OptAddress(Option):
    """IP address option"""
    pass


class OptPath(Option):
    """File path option"""
    pass


class OptEnum(Option):
    """Enumeration option"""
    
    def __init__(self, name: str, required: bool = False, default: Any = None,
                 description: str = '', enums: Optional[List[str]] = None, advanced: bool = False):
        """
        Initialize enum option
        
        Args:
            name: Option name
            required: Whether option is required
            default: Default value
            description: Option description
            enums: List of valid values
            advanced: Whether this is an advanced option
        """
        super().__init__(name, required, default, description, advanced)
        self.enums = enums or []
        
    def validate(self, value: Any) -> bool:
        """Validate enum value"""
        if not super().validate(value):
            return False
        if value is not None and self.enums:
            return value in self.enums
        return True
