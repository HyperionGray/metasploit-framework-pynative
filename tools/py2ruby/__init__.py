#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
Python to Ruby Transpiler Package

A modular transpiler that converts Python code to Ruby, organized into
focused modules for maintainability and extensibility.
"""

from .transpiler import PythonToRubyTranspiler
from .config import (
    MODULE_MAPPINGS,
    METHOD_MAPPINGS,
    OPERATOR_MAPPINGS,
    MAGIC_METHOD_MAPPINGS,
    TYPE_MAPPINGS,
    EXCEPTION_MAPPINGS
)
from .code_generator import RubyCodeGenerator

__version__ = "1.0.0"
__author__ = "Metasploit Framework Python Migration Team"

__all__ = [
    'PythonToRubyTranspiler',
    'RubyCodeGenerator',
    'MODULE_MAPPINGS',
    'METHOD_MAPPINGS',
    'OPERATOR_MAPPINGS',
    'MAGIC_METHOD_MAPPINGS',
    'TYPE_MAPPINGS',
    'EXCEPTION_MAPPINGS'
]