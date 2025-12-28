#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
AST visitor modules for Python to Ruby transpilation.

This module contains specialized AST visitors for different types of
Python constructs, organized by functionality.
"""

import ast
from typing import List, Optional
from .config import (
    MODULE_MAPPINGS, METHOD_MAPPINGS, OPERATOR_MAPPINGS,
    MAGIC_METHOD_MAPPINGS, TYPE_MAPPINGS, EXCEPTION_MAPPINGS
)
from .code_generator import RubyCodeGenerator


class ImportVisitor:
    """Handles Python import statements."""
    
    def __init__(self, generator: RubyCodeGenerator):
        self.generator = generator
    
    def visit_import(self, node: ast.Import):
        """Visit import statement: import x, y, z"""
        for alias in node.names:
            module_name = alias.name
            ruby_module = MODULE_MAPPINGS.get(module_name, module_name)
            
            if ruby_module:
                if alias.asname:
                    self.generator.write(f"require '{ruby_module.lower()}'")
                    self.generator.write(f"{alias.asname} = {ruby_module}")
                else:
                    self.generator.write(f"require '{ruby_module.lower()}'")
    
    def visit_import_from(self, node: ast.ImportFrom):
        """Visit from x import y statement."""
        module = node.module or ""
        ruby_module = MODULE_MAPPINGS.get(module, module)
        
        if ruby_module:
            self.generator.write(f"require '{ruby_module.lower()}'")


class FunctionVisitor:
    """Handles Python function definitions."""
    
    def __init__(self, generator: RubyCodeGenerator):
        self.generator = generator
        self.in_class = False
    
    def visit_function_def(self, node: ast.FunctionDef):
        """Visit function definition."""
        func_name = self._convert_function_name(node.name)
        args = self._convert_arguments(node.args)
        
        # Write function definition
        if args:
            args_str = ", ".join(args)
            self.generator.write(f"def {func_name}({args_str})")
        else:
            self.generator.write(f"def {func_name}")
        
        self.generator.indent()
        
        # Handle function body
        if node.body:
            for stmt in node.body:
                # This would be handled by the main transpiler
                pass
        else:
            self.generator.write("# Empty function body")
        
        self.generator.dedent()
        self.generator.write("end")
        self.generator.write("")
    
    def _convert_function_name(self, name: str) -> str:
        """Convert Python function name to Ruby equivalent."""
        if self.in_class and name in MAGIC_METHOD_MAPPINGS:
            return MAGIC_METHOD_MAPPINGS[name]
        
        if name.startswith('__') and name.endswith('__') and self.in_class:
            self.generator.write_comment(f"WARNING: Python magic method {name} may need manual conversion")
        
        return name
    
    def _convert_arguments(self, args: ast.arguments) -> List[str]:
        """Convert Python function arguments to Ruby format."""
        ruby_args = []
        
        # Regular arguments
        for arg in args.args:
            ruby_args.append(arg.arg)
        
        # Default arguments
        defaults_start = len(args.args) - len(args.defaults)
        for i, default in enumerate(args.defaults):
            arg_index = defaults_start + i
            arg_name = args.args[arg_index].arg
            # For now, just note that there's a default
            # The actual default value would need to be converted
            ruby_args[arg_index] = f"{arg_name} = nil"  # Simplified
        
        # *args equivalent
        if args.vararg:
            ruby_args.append(f"*{args.vararg.arg}")
        
        # **kwargs equivalent
        if args.kwarg:
            ruby_args.append(f"**{args.kwarg.arg}")
        
        return ruby_args


class ClassVisitor:
    """Handles Python class definitions."""
    
    def __init__(self, generator: RubyCodeGenerator):
        self.generator = generator
    
    def visit_class_def(self, node: ast.ClassDef):
        """Visit class definition."""
        class_name = node.name
        
        # Handle inheritance
        if node.bases:
            # For simplicity, take the first base class
            base_class = node.bases[0]
            if isinstance(base_class, ast.Name):
                superclass = base_class.id
                self.generator.write(f"class {class_name} < {superclass}")
            else:
                self.generator.write(f"class {class_name}")
                self.generator.write_comment("Complex inheritance - manual review needed")
        else:
            self.generator.write(f"class {class_name}")
        
        self.generator.indent()
        
        # Handle class body
        if node.body:
            for stmt in node.body:
                # This would be handled by the main transpiler
                pass
        else:
            self.generator.write("# Empty class body")
        
        self.generator.dedent()
        self.generator.write("end")
        self.generator.write("")


class ExpressionVisitor:
    """Handles Python expressions."""
    
    def __init__(self, generator: RubyCodeGenerator):
        self.generator = generator
    
    def visit_call(self, node: ast.Call) -> str:
        """Visit function/method call."""
        # Get the function/method name
        if isinstance(node.func, ast.Name):
            func_name = node.func.id
            ruby_func = METHOD_MAPPINGS.get(func_name, func_name)
            
            # Convert arguments
            args = []
            for arg in node.args:
                args.append(self._convert_expression(arg))
            
            if args:
                args_str = ", ".join(args)
                return f"{ruby_func}({args_str})"
            else:
                return ruby_func
        
        elif isinstance(node.func, ast.Attribute):
            # Method call on an object
            receiver = self._convert_expression(node.func.value)
            method = node.func.attr
            ruby_method = METHOD_MAPPINGS.get(method, method)
            
            args = []
            for arg in node.args:
                args.append(self._convert_expression(arg))
            
            if args:
                args_str = ", ".join(args)
                return f"{receiver}.{ruby_method}({args_str})"
            else:
                return f"{receiver}.{ruby_method}"
        
        return "# Complex function call - manual review needed"
    
    def _convert_expression(self, node: ast.AST) -> str:
        """Convert a Python expression to Ruby."""
        if isinstance(node, ast.Constant):
            return self._convert_constant(node.value)
        elif isinstance(node, ast.Name):
            return node.id
        elif isinstance(node, ast.Str):  # For older Python versions
            return f'"{node.s}"'
        elif isinstance(node, ast.Num):  # For older Python versions
            return str(node.n)
        else:
            return "# Complex expression - manual review needed"
    
    def _convert_constant(self, value) -> str:
        """Convert Python constant to Ruby equivalent."""
        if value is None:
            return "nil"
        elif value is True:
            return "true"
        elif value is False:
            return "false"
        elif isinstance(value, str):
            return f'"{value}"'
        else:
            return str(value)


class ControlFlowVisitor:
    """Handles Python control flow statements."""
    
    def __init__(self, generator: RubyCodeGenerator):
        self.generator = generator
    
    def visit_if(self, node: ast.If):
        """Visit if statement."""
        condition = self._convert_condition(node.test)
        self.generator.write(f"if {condition}")
        self.generator.indent()
        
        # Handle if body
        for stmt in node.body:
            # This would be handled by the main transpiler
            pass
        
        self.generator.dedent()
        
        # Handle else/elif
        if node.orelse:
            if len(node.orelse) == 1 and isinstance(node.orelse[0], ast.If):
                # This is an elif
                elif_node = node.orelse[0]
                elif_condition = self._convert_condition(elif_node.test)
                self.generator.write(f"elsif {elif_condition}")
                self.generator.indent()
                
                for stmt in elif_node.body:
                    # This would be handled by the main transpiler
                    pass
                
                self.generator.dedent()
            else:
                # This is an else
                self.generator.write("else")
                self.generator.indent()
                
                for stmt in node.orelse:
                    # This would be handled by the main transpiler
                    pass
                
                self.generator.dedent()
        
        self.generator.write("end")
    
    def visit_while(self, node: ast.While):
        """Visit while loop."""
        condition = self._convert_condition(node.test)
        self.generator.write(f"while {condition}")
        self.generator.indent()
        
        for stmt in node.body:
            # This would be handled by the main transpiler
            pass
        
        self.generator.dedent()
        self.generator.write("end")
    
    def visit_for(self, node: ast.For):
        """Visit for loop."""
        target = node.target.id if isinstance(node.target, ast.Name) else "item"
        
        if isinstance(node.iter, ast.Call) and isinstance(node.iter.func, ast.Name):
            if node.iter.func.id == "range":
                # Handle range() specially
                if len(node.iter.args) == 1:
                    # range(n) -> (0...n).each
                    end_val = self._convert_expression(node.iter.args[0])
                    self.generator.write(f"(0...{end_val}).each do |{target}|")
                elif len(node.iter.args) == 2:
                    # range(start, end) -> (start...end).each
                    start_val = self._convert_expression(node.iter.args[0])
                    end_val = self._convert_expression(node.iter.args[1])
                    self.generator.write(f"({start_val}...{end_val}).each do |{target}|")
                else:
                    # More complex range - simplified
                    self.generator.write(f"# Complex range - manual review needed")
                    self.generator.write(f"# Original: for {target} in range(...)")
            else:
                # Other iterables
                iterable = self._convert_expression(node.iter)
                self.generator.write(f"{iterable}.each do |{target}|")
        else:
            iterable = self._convert_expression(node.iter)
            self.generator.write(f"{iterable}.each do |{target}|")
        
        self.generator.indent()
        
        for stmt in node.body:
            # This would be handled by the main transpiler
            pass
        
        self.generator.dedent()
        self.generator.write("end")
    
    def _convert_condition(self, node: ast.AST) -> str:
        """Convert Python condition to Ruby."""
        if isinstance(node, ast.Compare):
            left = self._convert_expression(node.left)
            
            # Handle multiple comparisons
            if len(node.ops) == 1 and len(node.comparators) == 1:
                op = node.ops[0]
                right = self._convert_expression(node.comparators[0])
                
                if isinstance(op, ast.Eq):
                    return f"{left} == {right}"
                elif isinstance(op, ast.NotEq):
                    return f"{left} != {right}"
                elif isinstance(op, ast.Lt):
                    return f"{left} < {right}"
                elif isinstance(op, ast.LtE):
                    return f"{left} <= {right}"
                elif isinstance(op, ast.Gt):
                    return f"{left} > {right}"
                elif isinstance(op, ast.GtE):
                    return f"{left} >= {right}"
                elif isinstance(op, ast.In):
                    return f"{right}.include?({left})"
                elif isinstance(op, ast.NotIn):
                    return f"!{right}.include?({left})"
        
        # Fallback for complex conditions
        return "# Complex condition - manual review needed"
    
    def _convert_expression(self, node: ast.AST) -> str:
        """Convert expression (shared with ExpressionVisitor)."""
        if isinstance(node, ast.Constant):
            return self._convert_constant(node.value)
        elif isinstance(node, ast.Name):
            return node.id
        else:
            return "# Complex expression"
    
    def _convert_constant(self, value) -> str:
        """Convert constant (shared with ExpressionVisitor)."""
        if value is None:
            return "nil"
        elif value is True:
            return "true"
        elif value is False:
            return "false"
        elif isinstance(value, str):
            return f'"{value}"'
        else:
            return str(value)