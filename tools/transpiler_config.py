#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
Transpiler Configuration Module

Contains all language mappings and configuration data for Python to Ruby transpilation.
This module centralizes all mapping data to improve maintainability and reduce
the size of the main transpiler class.

Author: Metasploit Framework Python Migration Team
License: BSD-3-Clause
"""

from typing import Dict, Set


class TranspilerMappings:
    """Centralized mappings for Python to Ruby transpilation."""
    
    # Python stdlib to Ruby mappings
    MODULE_MAPPINGS: Dict[str, str] = {
        'os': 'FileUtils',
        'os.path': 'File',
        'sys': '',  # Ruby has $0, $*, etc.
        're': '',  # Ruby has built-in regex
        'json': 'JSON',
        'time': 'Time',
        'datetime': 'Time',
        'random': 'Random',
        'hashlib': 'Digest',
        'base64': 'Base64',
        'urllib': 'URI',
        'socket': 'Socket',
        'struct': '',  # Ruby has pack/unpack
    }
    
    # Python to Ruby method mappings
    METHOD_MAPPINGS: Dict[str, str] = {
        'append': 'push',
        'extend': 'concat',
        'pop': 'pop',
        'remove': 'delete',
        'insert': 'insert',
        'index': 'index',
        'count': 'count',
        'sort': 'sort!',
        'reverse': 'reverse!',
        'upper': 'upcase',
        'lower': 'downcase',
        'strip': 'strip',
        'lstrip': 'lstrip',
        'rstrip': 'rstrip',
        'split': 'split',
        'join': 'join',
        'replace': 'gsub',
        'startswith': 'start_with?',
        'endswith': 'end_with?',
        'format': '%',  # Use Ruby string interpolation
        'len': 'length',
        'str': 'to_s',
        'int': 'to_i',
        'float': 'to_f',
        'bool': 'to_bool',
        'list': 'to_a',
        'dict': 'to_h',
        'keys': 'keys',
        'values': 'values',
        'items': 'to_a',
        'get': 'fetch',
        'update': 'merge!',
        'copy': 'dup',
        'clear': 'clear',
        'isinstance': 'is_a?',
        'hasattr': 'respond_to?',
    }
    
    # Python operators to Ruby operators
    OPERATOR_MAPPINGS: Dict[str, str] = {
        'and': '&&',
        'or': '||',
        'not': '!',
        'is': '==',
        'is not': '!=',
        'in': 'include?',
        'not in': '!include?',
        '//': '/',  # Integer division
        '**': '**',  # Exponentiation
        '%': '%',   # Modulo
    }
    
    # Python built-in functions to Ruby equivalents
    BUILTIN_MAPPINGS: Dict[str, str] = {
        'print': 'puts',
        'input': 'gets.chomp',
        'range': 'Range.new',
        'enumerate': 'each_with_index',
        'zip': 'zip',
        'map': 'map',
        'filter': 'select',
        'reduce': 'reduce',
        'sum': 'sum',
        'min': 'min',
        'max': 'max',
        'sorted': 'sort',
        'reversed': 'reverse',
        'any': 'any?',
        'all': 'all?',
        'abs': 'abs',
        'round': 'round',
        'open': 'File.open',
    }
    
    # Python exception types to Ruby exception types
    EXCEPTION_MAPPINGS: Dict[str, str] = {
        'Exception': 'StandardError',
        'ValueError': 'ArgumentError',
        'TypeError': 'TypeError',
        'KeyError': 'KeyError',
        'IndexError': 'IndexError',
        'AttributeError': 'NoMethodError',
        'ImportError': 'LoadError',
        'IOError': 'IOError',
        'OSError': 'SystemCallError',
        'RuntimeError': 'RuntimeError',
        'NotImplementedError': 'NotImplementedError',
        'StopIteration': 'StopIteration',
    }
    
    # Python keywords that need special handling in Ruby
    RESERVED_KEYWORDS: Set[str] = {
        'and', 'or', 'not', 'is', 'in', 'lambda', 'def', 'class',
        'if', 'elif', 'else', 'for', 'while', 'try', 'except',
        'finally', 'with', 'as', 'import', 'from', 'global',
        'nonlocal', 'yield', 'return', 'break', 'continue', 'pass'
    }
    
    # Ruby keywords that conflict with Python identifiers
    RUBY_KEYWORDS: Set[str] = {
        'begin', 'rescue', 'ensure', 'end', 'case', 'when', 'then',
        'unless', 'until', 'redo', 'retry', 'next', 'alias', 'undef',
        'super', 'self', 'nil', 'true', 'false', 'module', 'require'
    }


class TranspilerConfig:
    """Configuration settings for the transpiler."""
    
    # Default indentation settings
    DEFAULT_INDENT = "  "
    
    # File extensions
    PYTHON_EXTENSIONS = {'.py', '.pyw'}
    RUBY_EXTENSIONS = {'.rb'}
    
    # Encoding settings
    DEFAULT_ENCODING = 'utf-8'
    
    # Output formatting options
    ADD_COMMENTS = True
    PRESERVE_DOCSTRINGS = True
    ADD_TYPE_HINTS = False
    
    # Transpilation options
    STRICT_MODE = False  # If True, fail on unsupported constructs
    VERBOSE_OUTPUT = False
    
    # Ruby style preferences
    USE_SNAKE_CASE = True
    USE_QUESTION_MARKS = True  # For boolean methods
    USE_EXCLAMATION_MARKS = True  # For mutating methods
    
    @classmethod
    def get_output_filename(cls, input_filename: str, output_filename: str = None) -> str:
        """Generate output filename for Ruby file."""
        if output_filename:
            return output_filename
        
        # Replace Python extension with Ruby extension
        for py_ext in cls.PYTHON_EXTENSIONS:
            if input_filename.endswith(py_ext):
                return input_filename[:-len(py_ext)] + '.rb'
        
        # If no Python extension found, just add .rb
        return input_filename + '.rb'