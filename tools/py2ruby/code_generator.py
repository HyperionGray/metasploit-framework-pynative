#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
Code generation utilities for Python to Ruby transpilation.

This module provides utilities for generating Ruby code with proper
indentation, formatting, and structure.
"""

from typing import List


class RubyCodeGenerator:
    """Utility class for generating properly formatted Ruby code."""
    
    def __init__(self, indent_string: str = "  "):
        self.output: List[str] = []
        self.indent_level: int = 0
        self.indent_string: str = indent_string
    
    def indent(self):
        """Increase indentation level."""
        self.indent_level += 1
    
    def dedent(self):
        """Decrease indentation level."""
        self.indent_level = max(0, self.indent_level - 1)
    
    def write(self, code: str):
        """Write code with current indentation."""
        if code.strip():
            self.output.append(self.indent_string * self.indent_level + code)
        else:
            self.output.append("")
    
    def write_block(self, lines: List[str]):
        """Write multiple lines of code."""
        for line in lines:
            self.write(line)
    
    def write_comment(self, comment: str):
        """Write a Ruby comment."""
        self.write(f"# {comment}")
    
    def write_header(self):
        """Write standard Ruby file header."""
        self.write("#!/usr/bin/env ruby")
        self.write("# -*- coding: utf-8 -*-")
        self.write("")
        self.write("# Transpiled from Python to Ruby")
        self.write("")
    
    def get_code(self) -> str:
        """Get the generated Ruby code."""
        return "\n".join(self.output)
    
    def clear(self):
        """Clear the generated code."""
        self.output.clear()
        self.indent_level = 0


def format_ruby_string(value: str) -> str:
    """Format a Python string literal as a Ruby string literal."""
    # Handle triple quotes
    if value.startswith('"""') or value.startswith("'''"):
        # Convert to Ruby heredoc
        content = value[3:-3]
        return f'<<~EOF\n{content}\nEOF'
    
    # Handle regular strings
    if value.startswith('"'):
        return value  # Already double-quoted
    elif value.startswith("'"):
        # Convert single quotes to double quotes for consistency
        content = value[1:-1]
        # Escape any existing double quotes
        content = content.replace('"', '\\"')
        return f'"{content}"'
    
    return f'"{value}"'


def format_ruby_array(elements: List[str]) -> str:
    """Format a list of elements as a Ruby array."""
    if not elements:
        return "[]"
    
    if len(elements) == 1:
        return f"[{elements[0]}]"
    
    # Multi-line array for readability
    formatted_elements = ",\n  ".join(elements)
    return f"[\n  {formatted_elements}\n]"


def format_ruby_hash(pairs: List[tuple]) -> str:
    """Format key-value pairs as a Ruby hash."""
    if not pairs:
        return "{}"
    
    if len(pairs) == 1:
        key, value = pairs[0]
        return f"{{{key} => {value}}}"
    
    # Multi-line hash for readability
    formatted_pairs = []
    for key, value in pairs:
        formatted_pairs.append(f"{key} => {value}")
    
    formatted_content = ",\n  ".join(formatted_pairs)
    return f"{{\n  {formatted_content}\n}}"


def format_ruby_method_call(receiver: str, method: str, args: List[str] = None) -> str:
    """Format a Ruby method call."""
    if args is None:
        args = []
    
    if not args:
        if receiver:
            return f"{receiver}.{method}"
        else:
            return method
    
    args_str = ", ".join(args)
    if receiver:
        return f"{receiver}.{method}({args_str})"
    else:
        return f"{method}({args_str})"


def format_ruby_class_definition(class_name: str, superclass: str = None) -> str:
    """Format a Ruby class definition."""
    if superclass:
        return f"class {class_name} < {superclass}"
    else:
        return f"class {class_name}"


def format_ruby_method_definition(method_name: str, args: List[str] = None) -> str:
    """Format a Ruby method definition."""
    if args is None:
        args = []
    
    if not args:
        return f"def {method_name}"
    
    args_str = ", ".join(args)
    return f"def {method_name}({args_str})"


def sanitize_ruby_identifier(name: str) -> str:
    """Sanitize a Python identifier for use in Ruby."""
    # Ruby identifiers can't start with uppercase (those are constants)
    # unless it's actually meant to be a constant
    if name.isupper():
        return name  # Keep constants as-is
    
    # Convert Python naming conventions to Ruby
    if name.startswith('__') and name.endswith('__'):
        # Magic methods are handled elsewhere
        return name
    
    # Convert snake_case (already Ruby style)
    return name


def format_ruby_require(module_name: str) -> str:
    """Format a Ruby require statement."""
    return f"require '{module_name}'"


def format_ruby_conditional(condition: str, if_body: List[str], else_body: List[str] = None) -> List[str]:
    """Format a Ruby conditional statement."""
    lines = [f"if {condition}"]
    lines.extend([f"  {line}" for line in if_body])
    
    if else_body:
        lines.append("else")
        lines.extend([f"  {line}" for line in else_body])
    
    lines.append("end")
    return lines


def format_ruby_loop(loop_type: str, condition: str, body: List[str]) -> List[str]:
    """Format a Ruby loop statement."""
    if loop_type == "while":
        lines = [f"while {condition}"]
    elif loop_type == "until":
        lines = [f"until {condition}"]
    else:
        lines = [f"{condition}.each do"]
    
    lines.extend([f"  {line}" for line in body])
    lines.append("end")
    return lines