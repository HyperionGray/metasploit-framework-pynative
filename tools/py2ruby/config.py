#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
Configuration mappings for Python to Ruby transpilation.

This module contains all the mapping dictionaries used to convert
Python constructs to their Ruby equivalents.
"""

# Python stdlib to Ruby mappings
MODULE_MAPPINGS = {
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
METHOD_MAPPINGS = {
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
    'getattr': 'send',
    'setattr': 'send',
    'print': 'puts',
    'input': 'gets.chomp',
    'open': 'File.open',
    'read': 'read',
    'write': 'write',
    'close': 'close',
    'range': 'Range.new',
    'enumerate': 'each_with_index',
    'zip': 'zip',
    'map': 'map',
    'filter': 'select',
    'reduce': 'reduce',
    'any': 'any?',
    'all': 'all?',
    'sum': 'sum',
    'min': 'min',
    'max': 'max',
    'sorted': 'sort',
    'reversed': 'reverse',
}

# Python operators to Ruby operators
OPERATOR_MAPPINGS = {
    'and': '&&',
    'or': '||',
    'not': '!',
    'is': '==',
    'is not': '!=',
    'in': 'include?',
    'not in': '!include?',
}

# Python magic methods to Ruby equivalents
MAGIC_METHOD_MAPPINGS = {
    '__init__': 'initialize',
    '__str__': 'to_s',
    '__repr__': 'inspect',
    '__len__': 'length',
    '__eq__': '==',
    '__ne__': '!=',
    '__lt__': '<',
    '__le__': '<=',
    '__gt__': '>',
    '__ge__': '>=',
    '__add__': '+',
    '__sub__': '-',
    '__mul__': '*',
    '__div__': '/',
    '__mod__': '%',
    '__pow__': '**',
    '__and__': '&',
    '__or__': '|',
    '__xor__': '^',
    '__lshift__': '<<',
    '__rshift__': '>>',
    '__getitem__': '[]',
    '__setitem__': '[]=',
    '__contains__': 'include?',
    '__iter__': 'each',
    '__next__': 'next',
    '__call__': 'call',
    '__enter__': 'enter',
    '__exit__': 'exit',
}

# Python built-in types to Ruby equivalents
TYPE_MAPPINGS = {
    'list': 'Array',
    'dict': 'Hash',
    'set': 'Set',
    'tuple': 'Array',  # Ruby doesn't have immutable arrays
    'str': 'String',
    'int': 'Integer',
    'float': 'Float',
    'bool': 'TrueClass/FalseClass',
    'bytes': 'String',  # Ruby strings are byte arrays
    'bytearray': 'String',
    'None': 'nil',
    'True': 'true',
    'False': 'false',
}

# Python exception types to Ruby equivalents
EXCEPTION_MAPPINGS = {
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
    'FileNotFoundError': 'Errno::ENOENT',
    'PermissionError': 'Errno::EACCES',
    'TimeoutError': 'Timeout::Error',
}