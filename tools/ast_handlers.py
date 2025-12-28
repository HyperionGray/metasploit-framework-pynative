#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
AST Node Handlers for Python to Ruby Transpilation

This module contains specialized handlers for different types of Python AST nodes.
Each handler is responsible for converting a specific type of Python construct
to its Ruby equivalent.

Author: Metasploit Framework Python Migration Team
License: BSD-3-Clause
"""

import ast
from typing import List, Optional, Any
from .transpiler_config import TranspilerMappings, TranspilerConfig


class BaseNodeHandler:
    """Base class for AST node handlers."""
    
    def __init__(self, transpiler):
        self.transpiler = transpiler
        self.mappings = TranspilerMappings()
        self.config = TranspilerConfig()
    
    def handle(self, node: ast.AST) -> str:
        """Handle the given AST node and return Ruby code."""
        raise NotImplementedError("Subclasses must implement handle method")


class ExpressionHandler(BaseNodeHandler):
    """Handles Python expressions and converts them to Ruby."""
    
    def handle_name(self, node: ast.Name) -> str:
        """Handle Name nodes (variables, functions)."""
        name = node.id
        
        # Handle special Python names
        if name == 'None':
            return 'nil'
        elif name == 'True':
            return 'true'
        elif name == 'False':
            return 'false'
        elif name == 'self':
            return 'self'
        
        return name
    
    def handle_constant(self, node: ast.Constant) -> str:
        """Handle Constant nodes (literals)."""
        value = node.value
        
        if value is None:
            return 'nil'
        elif isinstance(value, bool):
            return 'true' if value else 'false'
        elif isinstance(value, str):
            # Handle string literals with proper escaping
            return repr(value)
        elif isinstance(value, (int, float)):
            return str(value)
        else:
            return str(value)
    
    def handle_binop(self, node: ast.BinOp) -> str:
        """Handle binary operations."""
        left = self.transpiler.visit(node.left)
        right = self.transpiler.visit(node.right)
        
        # Map Python operators to Ruby
        op_map = {
            ast.Add: '+',
            ast.Sub: '-',
            ast.Mult: '*',
            ast.Div: '/',
            ast.FloorDiv: '/',  # Ruby doesn't have floor division operator
            ast.Mod: '%',
            ast.Pow: '**',
            ast.LShift: '<<',
            ast.RShift: '>>',
            ast.BitOr: '|',
            ast.BitXor: '^',
            ast.BitAnd: '&',
        }
        
        op = op_map.get(type(node.op), '?')
        return f"{left} {op} {right}"
    
    def handle_compare(self, node: ast.Compare) -> str:
        """Handle comparison operations."""
        left = self.transpiler.visit(node.left)
        
        # Handle multiple comparisons (a < b < c)
        parts = [left]
        
        for op, comparator in zip(node.ops, node.comparators):
            right = self.transpiler.visit(comparator)
            
            # Map comparison operators
            op_map = {
                ast.Eq: '==',
                ast.NotEq: '!=',
                ast.Lt: '<',
                ast.LtE: '<=',
                ast.Gt: '>',
                ast.GtE: '>=',
                ast.Is: '==',  # Ruby doesn't have 'is'
                ast.IsNot: '!=',
                ast.In: '.include?',
                ast.NotIn: '!.include?',
            }
            
            ruby_op = op_map.get(type(op), '==')
            
            if isinstance(op, ast.In):
                parts.append(f"{right}.include?({left})")
            elif isinstance(op, ast.NotIn):
                parts.append(f"!{right}.include?({left})")
            else:
                parts.append(f"{left} {ruby_op} {right}")
            
            left = right  # For chained comparisons
        
        return ' && '.join(parts[1:]) if len(parts) > 2 else parts[-1]


class StatementHandler(BaseNodeHandler):
    """Handles Python statements and converts them to Ruby."""
    
    def handle_assign(self, node: ast.Assign) -> str:
        """Handle assignment statements."""
        value = self.transpiler.visit(node.value)
        
        assignments = []
        for target in node.targets:
            if isinstance(target, ast.Name):
                assignments.append(f"{target.id} = {value}")
            elif isinstance(target, ast.Tuple):
                # Multiple assignment
                names = [elt.id for elt in target.elts if isinstance(elt, ast.Name)]
                assignments.append(f"{', '.join(names)} = {value}")
            else:
                # Complex assignment (attribute, subscript, etc.)
                target_str = self.transpiler.visit(target)
                assignments.append(f"{target_str} = {value}")
        
        return '\n'.join(assignments)
    
    def handle_if(self, node: ast.If) -> str:
        """Handle if statements."""
        test = self.transpiler.visit(node.test)
        
        # Generate if block
        lines = [f"if {test}"]
        
        # Add body with increased indentation
        self.transpiler.indent_level += 1
        for stmt in node.body:
            lines.append(self.transpiler.get_indent() + self.transpiler.visit(stmt))
        self.transpiler.indent_level -= 1
        
        # Handle elsif/else
        if node.orelse:
            if len(node.orelse) == 1 and isinstance(node.orelse[0], ast.If):
                # elsif case
                elsif_node = node.orelse[0]
                elsif_test = self.transpiler.visit(elsif_node.test)
                lines.append(f"elsif {elsif_test}")
                
                self.transpiler.indent_level += 1
                for stmt in elsif_node.body:
                    lines.append(self.transpiler.get_indent() + self.transpiler.visit(stmt))
                self.transpiler.indent_level -= 1
                
                # Handle nested else
                if elsif_node.orelse:
                    lines.append("else")
                    self.transpiler.indent_level += 1
                    for stmt in elsif_node.orelse:
                        lines.append(self.transpiler.get_indent() + self.transpiler.visit(stmt))
                    self.transpiler.indent_level -= 1
            else:
                # else case
                lines.append("else")
                self.transpiler.indent_level += 1
                for stmt in node.orelse:
                    lines.append(self.transpiler.get_indent() + self.transpiler.visit(stmt))
                self.transpiler.indent_level -= 1
        
        lines.append("end")
        return '\n'.join(lines)
    
    def handle_for(self, node: ast.For) -> str:
        """Handle for loops."""
        target = self.transpiler.visit(node.target)
        iter_expr = self.transpiler.visit(node.iter)
        
        # Generate for loop
        lines = [f"{iter_expr}.each do |{target}|"]
        
        # Add body with increased indentation
        self.transpiler.indent_level += 1
        for stmt in node.body:
            lines.append(self.transpiler.get_indent() + self.transpiler.visit(stmt))
        self.transpiler.indent_level -= 1
        
        lines.append("end")
        return '\n'.join(lines)
    
    def handle_while(self, node: ast.While) -> str:
        """Handle while loops."""
        test = self.transpiler.visit(node.test)
        
        lines = [f"while {test}"]
        
        # Add body with increased indentation
        self.transpiler.indent_level += 1
        for stmt in node.body:
            lines.append(self.transpiler.get_indent() + self.transpiler.visit(stmt))
        self.transpiler.indent_level -= 1
        
        lines.append("end")
        return '\n'.join(lines)


class FunctionHandler(BaseNodeHandler):
    """Handles Python function definitions and calls."""
    
    def handle_function_def(self, node: ast.FunctionDef) -> str:
        """Handle function definitions."""
        name = node.name
        
        # Handle arguments
        args = []
        for arg in node.args.args:
            args.append(arg.arg)
        
        # Handle default arguments
        defaults = node.args.defaults
        if defaults:
            num_defaults = len(defaults)
            for i, default in enumerate(defaults):
                arg_index = len(args) - num_defaults + i
                default_value = self.transpiler.visit(default)
                args[arg_index] = f"{args[arg_index]} = {default_value}"
        
        args_str = ', '.join(args)
        
        lines = [f"def {name}({args_str})"]
        
        # Add docstring as comment if present
        if (node.body and isinstance(node.body[0], ast.Expr) and 
            isinstance(node.body[0].value, ast.Constant) and 
            isinstance(node.body[0].value.value, str)):
            docstring = node.body[0].value.value
            for line in docstring.split('\n'):
                if line.strip():
                    lines.append(f"  # {line.strip()}")
            body_start = 1
        else:
            body_start = 0
        
        # Add function body
        self.transpiler.indent_level += 1
        for stmt in node.body[body_start:]:
            lines.append(self.transpiler.get_indent() + self.transpiler.visit(stmt))
        self.transpiler.indent_level -= 1
        
        lines.append("end")
        return '\n'.join(lines)
    
    def handle_call(self, node: ast.Call) -> str:
        """Handle function calls."""
        func = self.transpiler.visit(node.func)
        
        # Handle built-in functions
        if isinstance(node.func, ast.Name):
            func_name = node.func.id
            if func_name in self.mappings.BUILTIN_MAPPINGS:
                func = self.mappings.BUILTIN_MAPPINGS[func_name]
        
        # Handle arguments
        args = []
        for arg in node.args:
            args.append(self.transpiler.visit(arg))
        
        # Handle keyword arguments
        for keyword in node.keywords:
            key = keyword.arg
            value = self.transpiler.visit(keyword.value)
            args.append(f"{key}: {value}")
        
        args_str = ', '.join(args)
        
        # Special handling for certain functions
        if func == 'puts' and not args:
            return 'puts'
        elif func == 'Range.new' and len(args) >= 2:
            # Convert range(start, stop) to (start...stop)
            if len(args) == 2:
                return f"({args[0]}...{args[1]})"
            else:
                return f"({args[0]}...{args[1]})"
        
        return f"{func}({args_str})"


class ClassHandler(BaseNodeHandler):
    """Handles Python class definitions."""
    
    def handle_class_def(self, node: ast.ClassDef) -> str:
        """Handle class definitions."""
        name = node.name
        
        # Handle inheritance
        bases = []
        for base in node.bases:
            bases.append(self.transpiler.visit(base))
        
        if bases:
            inheritance = f" < {bases[0]}"  # Ruby single inheritance
        else:
            inheritance = ""
        
        lines = [f"class {name}{inheritance}"]
        
        # Add class body
        self.transpiler.indent_level += 1
        self.transpiler.in_class = True
        self.transpiler.class_name = name
        
        for stmt in node.body:
            lines.append(self.transpiler.get_indent() + self.transpiler.visit(stmt))
        
        self.transpiler.in_class = False
        self.transpiler.class_name = None
        self.transpiler.indent_level -= 1
        
        lines.append("end")
        return '\n'.join(lines)