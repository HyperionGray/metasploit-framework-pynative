#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
Modular Python to Ruby Transpiler

A refactored, modular version of the Python to Ruby transpiler that
separates concerns into focused modules for better maintainability.
"""

import ast
from typing import Optional
from .config import (
    MODULE_MAPPINGS, METHOD_MAPPINGS, OPERATOR_MAPPINGS,
    MAGIC_METHOD_MAPPINGS, TYPE_MAPPINGS, EXCEPTION_MAPPINGS
)
from .code_generator import RubyCodeGenerator
from .visitors import (
    ImportVisitor, FunctionVisitor, ClassVisitor,
    ExpressionVisitor, ControlFlowVisitor
)


class PythonToRubyTranspiler(ast.NodeVisitor):
    """
    Modular AST-based Python to Ruby transpiler.
    
    This refactored version separates different types of AST node
    handling into focused visitor classes for better maintainability.
    """
    
    def __init__(self):
        self.generator = RubyCodeGenerator()
        self.in_class = False
        self.in_function = False
        self.class_name = None
        
        # Initialize specialized visitors
        self.import_visitor = ImportVisitor(self.generator)
        self.function_visitor = FunctionVisitor(self.generator)
        self.class_visitor = ClassVisitor(self.generator)
        self.expression_visitor = ExpressionVisitor(self.generator)
        self.control_flow_visitor = ControlFlowVisitor(self.generator)
    
    def get_ruby_code(self) -> str:
        """Get the generated Ruby code."""
        return self.generator.get_code()
    
    def visit_Module(self, node: ast.Module):
        """Visit module (top-level)."""
        self.generator.write_header()
        
        # Process all statements
        for stmt in node.body:
            self.visit(stmt)
    
    def visit_Import(self, node: ast.Import):
        """Visit import statement."""
        self.import_visitor.visit_import(node)
    
    def visit_ImportFrom(self, node: ast.ImportFrom):
        """Visit from x import y statement."""
        self.import_visitor.visit_import_from(node)
    
    def visit_FunctionDef(self, node: ast.FunctionDef):
        """Visit function definition."""
        old_in_function = self.in_function
        self.in_function = True
        self.function_visitor.in_class = self.in_class
        
        self.function_visitor.visit_function_def(node)
        
        # Visit function body
        self.generator.indent()
        for stmt in node.body:
            self.visit(stmt)
        self.generator.dedent()
        
        self.in_function = old_in_function
    
    def visit_ClassDef(self, node: ast.ClassDef):
        """Visit class definition."""
        old_in_class = self.in_class
        old_class_name = self.class_name
        
        self.in_class = True
        self.class_name = node.name
        
        self.class_visitor.visit_class_def(node)
        
        # Visit class body
        self.generator.indent()
        for stmt in node.body:
            self.visit(stmt)
        self.generator.dedent()
        
        self.in_class = old_in_class
        self.class_name = old_class_name
    
    def visit_If(self, node: ast.If):
        """Visit if statement."""
        self.control_flow_visitor.visit_if(node)
    
    def visit_While(self, node: ast.While):
        """Visit while loop."""
        self.control_flow_visitor.visit_while(node)
    
    def visit_For(self, node: ast.For):
        """Visit for loop."""
        self.control_flow_visitor.visit_for(node)
    
    def visit_Expr(self, node: ast.Expr):
        """Visit expression statement."""
        if isinstance(node.value, ast.Call):
            ruby_call = self.expression_visitor.visit_call(node.value)
            self.generator.write(ruby_call)
        else:
            self.generator.write("# Expression statement - manual review needed")
    
    def visit_Assign(self, node: ast.Assign):
        """Visit assignment statement."""
        if len(node.targets) == 1 and isinstance(node.targets[0], ast.Name):
            target = node.targets[0].id
            value = self._convert_value(node.value)
            self.generator.write(f"{target} = {value}")
        else:
            self.generator.write("# Complex assignment - manual review needed")
    
    def visit_Return(self, node: ast.Return):
        """Visit return statement."""
        if node.value:
            value = self._convert_value(node.value)
            self.generator.write(f"return {value}")
        else:
            self.generator.write("return")
    
    def visit_Pass(self, node: ast.Pass):
        """Visit pass statement."""
        self.generator.write("# pass")
    
    def visit_Break(self, node: ast.Break):
        """Visit break statement."""
        self.generator.write("break")
    
    def visit_Continue(self, node: ast.Continue):
        """Visit continue statement."""
        self.generator.write("next")
    
    def visit_Try(self, node: ast.Try):
        """Visit try/except statement."""
        self.generator.write("begin")
        self.generator.indent()
        
        # Try body
        for stmt in node.body:
            self.visit(stmt)
        
        self.generator.dedent()
        
        # Exception handlers
        for handler in node.handlers:
            if handler.type:
                if isinstance(handler.type, ast.Name):
                    exception_type = handler.type.id
                    ruby_exception = EXCEPTION_MAPPINGS.get(exception_type, exception_type)
                    if handler.name:
                        self.generator.write(f"rescue {ruby_exception} => {handler.name}")
                    else:
                        self.generator.write(f"rescue {ruby_exception}")
                else:
                    self.generator.write("rescue StandardError")
            else:
                self.generator.write("rescue")
            
            self.generator.indent()
            for stmt in handler.body:
                self.visit(stmt)
            self.generator.dedent()
        
        # Else clause (Ruby doesn't have this, so add comment)
        if node.orelse:
            self.generator.write("# Python 'else' clause - manual conversion needed")
            for stmt in node.orelse:
                self.visit(stmt)
        
        # Finally clause
        if node.finalbody:
            self.generator.write("ensure")
            self.generator.indent()
            for stmt in node.finalbody:
                self.visit(stmt)
            self.generator.dedent()
        
        self.generator.write("end")
    
    def visit_Raise(self, node: ast.Raise):
        """Visit raise statement."""
        if node.exc:
            if isinstance(node.exc, ast.Call) and isinstance(node.exc.func, ast.Name):
                exception_type = node.exc.func.id
                ruby_exception = EXCEPTION_MAPPINGS.get(exception_type, exception_type)
                
                if node.exc.args:
                    message = self._convert_value(node.exc.args[0])
                    self.generator.write(f"raise {ruby_exception}, {message}")
                else:
                    self.generator.write(f"raise {ruby_exception}")
            else:
                self.generator.write("raise # Complex raise - manual review needed")
        else:
            self.generator.write("raise")
    
    def visit_With(self, node: ast.With):
        """Visit with statement."""
        self.generator.write("# Python 'with' statement - manual conversion needed")
        self.generator.write("# Consider using Ruby blocks or ensure clauses")
        
        for stmt in node.body:
            self.visit(stmt)
    
    def _convert_value(self, node: ast.AST) -> str:
        """Convert a Python value to Ruby equivalent."""
        if isinstance(node, ast.Constant):
            return self._convert_constant(node.value)
        elif isinstance(node, ast.Name):
            return node.id
        elif isinstance(node, ast.Call):
            return self.expression_visitor.visit_call(node)
        elif isinstance(node, ast.List):
            elements = [self._convert_value(elem) for elem in node.elts]
            return f"[{', '.join(elements)}]"
        elif isinstance(node, ast.Dict):
            pairs = []
            for key, value in zip(node.keys, node.values):
                key_str = self._convert_value(key)
                value_str = self._convert_value(value)
                pairs.append(f"{key_str} => {value_str}")
            return f"{{{', '.join(pairs)}}}"
        elif isinstance(node, ast.Str):  # For older Python versions
            return f'"{node.s}"'
        elif isinstance(node, ast.Num):  # For older Python versions
            return str(node.n)
        else:
            return "# Complex value - manual review needed"
    
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
    
    def generic_visit(self, node):
        """Handle unimplemented node types."""
        node_type = type(node).__name__
        self.generator.write(f"# Unhandled node type: {node_type}")
        self.generator.write(f"# Manual conversion required")
        super().generic_visit(node)


def transpile_python_to_ruby(python_code: str) -> str:
    """
    Transpile Python code to Ruby.
    
    Args:
        python_code: Python source code as string
        
    Returns:
        Ruby source code as string
    """
    try:
        tree = ast.parse(python_code)
        transpiler = PythonToRubyTranspiler()
        transpiler.visit(tree)
        return transpiler.get_ruby_code()
    except SyntaxError as e:
        return f"# Syntax error in Python code: {e}\n# Please fix the Python code and try again."
    except Exception as e:
        return f"# Transpilation error: {e}\n# Manual conversion may be required."