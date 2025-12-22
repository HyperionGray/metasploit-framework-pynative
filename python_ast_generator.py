#!/usr/bin/env python3
"""
Python AST Generator for Ruby-to-Python Transpiler

This module provides Python AST generation capabilities to create
syntactically correct Python code from converted Ruby AST nodes.
"""

import ast
import sys
from typing import Dict, List, Any, Optional, Union, Tuple
from dataclasses import dataclass
from ruby_ast_parser import RubyASTNode


@dataclass
class PythonASTContext:
    """Context information for Python AST generation"""
    class_name: Optional[str] = None
    method_name: Optional[str] = None
    in_class: bool = False
    in_method: bool = False
    indent_level: int = 0
    imports: List[str] = None
    
    def __post_init__(self):
        if self.imports is None:
            self.imports = []


class PythonASTGenerator:
    """Generator for Python AST from Ruby AST nodes"""
    
    def __init__(self):
        self.context = PythonASTContext()
        self.node_converters = self._setup_node_converters()
    
    def _setup_node_converters(self) -> Dict[str, callable]:
        """Setup mapping of Ruby AST node types to Python conversion functions"""
        return {
            'program': self._convert_program,
            'class': self._convert_class,
            'module': self._convert_module,
            'def': self._convert_def,
            'call': self._convert_call,
            'method_add_arg': self._convert_method_add_arg,
            'assign': self._convert_assign,
            'var_field': self._convert_var_field,
            'var_ref': self._convert_var_ref,
            'const': self._convert_const,
            'const_ref': self._convert_const_ref,
            'hash': self._convert_hash,
            'assoc_new': self._convert_assoc_new,
            'array': self._convert_array,
            'string_literal': self._convert_string_literal,
            'string_content': self._convert_string_content,
            'tstring_content': self._convert_tstring_content,
            'symbol_literal': self._convert_symbol_literal,
            'symbol': self._convert_symbol,
            'if': self._convert_if,
            'unless': self._convert_unless,
            'while': self._convert_while,
            'for': self._convert_for,
            'block_var': self._convert_block_var,
            'brace_block': self._convert_brace_block,
            'do_block': self._convert_do_block,
            'return': self._convert_return,
            'yield': self._convert_yield,
            'binary': self._convert_binary,
            'unary': self._convert_unary,
            'paren': self._convert_paren,
            'int': self._convert_int,
            'float': self._convert_float,
            'rational': self._convert_rational,
            'imaginary': self._convert_imaginary,
            'kw': self._convert_kw,
            'regexp_literal': self._convert_regexp_literal,
            'literal': self._convert_literal,
        }
    
    def generate_python_ast(self, ruby_ast: RubyASTNode) -> ast.Module:
        """Generate Python AST from Ruby AST"""
        self.context = PythonASTContext()
        
        # Convert the Ruby AST to Python AST
        python_nodes = self._convert_node(ruby_ast)
        
        # Ensure we have a list of statements
        if not isinstance(python_nodes, list):
            python_nodes = [python_nodes] if python_nodes else []
        
        # Filter out None values
        python_nodes = [node for node in python_nodes if node is not None]
        
        # Create module with imports and converted statements
        imports = self._generate_imports()
        all_statements = imports + python_nodes
        
        return ast.Module(body=all_statements, type_ignores=[])
    
    def generate_python_code(self, ruby_ast: RubyASTNode) -> str:
        """Generate Python code string from Ruby AST"""
        python_ast = self.generate_python_ast(ruby_ast)
        return ast.unparse(python_ast)
    
    def _generate_imports(self) -> List[ast.stmt]:
        """Generate necessary import statements"""
        imports = []
        
        # Standard imports for Metasploit modules
        standard_imports = [
            'import sys',
            'import os',
            'import re',
            'import json',
            'import time',
            'import logging',
            'from typing import Dict, List, Optional, Any, Union'
        ]
        
        for import_stmt in standard_imports:
            if 'from' in import_stmt:
                # Handle 'from ... import ...' statements
                parts = import_stmt.split()
                module = parts[1]
                names = [ast.alias(name=name.strip(','), asname=None) 
                        for name in parts[3:]]
                imports.append(ast.ImportFrom(module=module, names=names, level=0))
            else:
                # Handle 'import ...' statements
                module_name = import_stmt.split()[1]
                imports.append(ast.Import(names=[ast.alias(name=module_name, asname=None)]))
        
        return imports
    
    def _convert_node(self, node: RubyASTNode) -> Union[ast.AST, List[ast.AST], None]:
        """Convert a Ruby AST node to Python AST node(s)"""
        if node is None:
            return None
        
        converter = self.node_converters.get(node.node_type)
        if converter:
            return converter(node)
        else:
            # Unknown node type - create a comment
            return ast.Expr(value=ast.Constant(
                value=f"# TODO: Convert Ruby {node.node_type} node"
            ))
    
    def _convert_children(self, node: RubyASTNode) -> List[ast.AST]:
        """Convert all children of a Ruby AST node"""
        results = []
        for child in node.children:
            converted = self._convert_node(child)
            if isinstance(converted, list):
                results.extend(converted)
            elif converted is not None:
                results.append(converted)
        return results
    
    # Node conversion methods
    def _convert_program(self, node: RubyASTNode) -> List[ast.stmt]:
        """Convert Ruby program node to Python module statements"""
        return self._convert_children(node)
    
    def _convert_class(self, node: RubyASTNode) -> ast.ClassDef:
        """Convert Ruby class to Python class"""
        if len(node.children) < 3:
            return None
        
        name_node = node.children[0]
        superclass_node = node.children[1]
        body_node = node.children[2]
        
        # Extract class name
        class_name = self._extract_name(name_node)
        
        # Handle superclass
        bases = []
        if superclass_node and superclass_node.node_type != 'literal':
            superclass_name = self._extract_name(superclass_node)
            if superclass_name:
                # Map Ruby superclasses to Python equivalents
                python_superclass = self._map_ruby_class_to_python(superclass_name)
                bases.append(ast.Name(id=python_superclass, ctx=ast.Load()))
        
        # Convert body
        old_context = self.context
        self.context.class_name = class_name
        self.context.in_class = True
        
        body_statements = []
        if body_node:
            body_converted = self._convert_node(body_node)
            if isinstance(body_converted, list):
                body_statements.extend(body_converted)
            elif body_converted:
                body_statements.append(body_converted)
        
        # Ensure class has at least a pass statement
        if not body_statements:
            body_statements = [ast.Pass()]
        
        self.context = old_context
        
        return ast.ClassDef(
            name=class_name,
            bases=bases,
            keywords=[],
            decorator_list=[],
            body=body_statements
        )
    
    def _convert_module(self, node: RubyASTNode) -> ast.ClassDef:
        """Convert Ruby module to Python class (modules become classes in Python)"""
        # Similar to class conversion but without inheritance
        if len(node.children) < 2:
            return None
        
        name_node = node.children[0]
        body_node = node.children[1]
        
        module_name = self._extract_name(name_node)
        
        # Convert body
        old_context = self.context
        self.context.class_name = module_name
        self.context.in_class = True
        
        body_statements = []
        if body_node:
            body_converted = self._convert_node(body_node)
            if isinstance(body_converted, list):
                body_statements.extend(body_converted)
            elif body_converted:
                body_statements.append(body_converted)
        
        if not body_statements:
            body_statements = [ast.Pass()]
        
        self.context = old_context
        
        return ast.ClassDef(
            name=module_name,
            bases=[],
            keywords=[],
            decorator_list=[],
            body=body_statements
        )
    
    def _convert_def(self, node: RubyASTNode) -> ast.FunctionDef:
        """Convert Ruby method definition to Python function"""
        if len(node.children) < 3:
            return None
        
        name_node = node.children[0]
        params_node = node.children[1]
        body_node = node.children[2]
        
        method_name = self._extract_name(name_node)
        
        # Convert parameters
        args = []
        if self.context.in_class:
            args.append(ast.arg(arg='self', annotation=None))
        
        if params_node and params_node.children:
            for param in params_node.children:
                param_name = self._extract_name(param)
                if param_name:
                    args.append(ast.arg(arg=param_name, annotation=None))
        
        # Convert body
        old_context = self.context
        self.context.method_name = method_name
        self.context.in_method = True
        
        body_statements = []
        if body_node:
            body_converted = self._convert_node(body_node)
            if isinstance(body_converted, list):
                body_statements.extend(body_converted)
            elif body_converted:
                body_statements.append(body_converted)
        
        if not body_statements:
            body_statements = [ast.Pass()]
        
        self.context = old_context
        
        return ast.FunctionDef(
            name=method_name,
            args=ast.arguments(
                posonlyargs=[],
                args=args,
                vararg=None,
                kwonlyargs=[],
                kw_defaults=[],
                kwarg=None,
                defaults=[]
            ),
            body=body_statements,
            decorator_list=[],
            returns=None
        )
    
    def _convert_call(self, node: RubyASTNode) -> ast.Call:
        """Convert Ruby method call to Python function call"""
        if len(node.children) < 3:
            return None
        
        receiver_node = node.children[0]
        method_node = node.children[1]
        args_node = node.children[2]
        
        # Convert receiver (object being called on)
        if receiver_node and receiver_node.node_type != 'literal':
            func = self._convert_node(receiver_node)
            method_name = self._extract_name(method_node)
            if method_name:
                func = ast.Attribute(value=func, attr=method_name, ctx=ast.Load())
        else:
            # No receiver, just method name
            method_name = self._extract_name(method_node)
            func = ast.Name(id=method_name, ctx=ast.Load())
        
        # Convert arguments
        args = []
        keywords = []
        
        if args_node and args_node.children:
            for arg in args_node.children:
                converted_arg = self._convert_node(arg)
                if converted_arg:
                    args.append(converted_arg)
        
        return ast.Call(func=func, args=args, keywords=keywords)
    
    def _convert_method_add_arg(self, node: RubyASTNode) -> ast.Call:
        """Convert Ruby method call with arguments"""
        if len(node.children) < 2:
            return None
        
        call_node = node.children[0]
        args_node = node.children[1]
        
        # Convert the base call
        call = self._convert_node(call_node)
        if not isinstance(call, ast.Call):
            return call
        
        # Add arguments
        if args_node and args_node.children:
            for arg in args_node.children:
                converted_arg = self._convert_node(arg)
                if converted_arg:
                    call.args.append(converted_arg)
        
        return call
    
    def _convert_assign(self, node: RubyASTNode) -> ast.Assign:
        """Convert Ruby assignment to Python assignment"""
        if len(node.children) < 2:
            return None
        
        lhs_node = node.children[0]
        rhs_node = node.children[1]
        
        # Convert left-hand side (target)
        target = self._convert_node(lhs_node)
        if not target:
            return None
        
        # Convert right-hand side (value)
        value = self._convert_node(rhs_node)
        if not value:
            value = ast.Constant(value=None)
        
        return ast.Assign(targets=[target], value=value)
    
    def _convert_var_field(self, node: RubyASTNode) -> ast.Name:
        """Convert Ruby variable field to Python name"""
        name = self._extract_name(node)
        if name:
            return ast.Name(id=name, ctx=ast.Store())
        return None
    
    def _convert_var_ref(self, node: RubyASTNode) -> ast.Name:
        """Convert Ruby variable reference to Python name"""
        name = self._extract_name(node)
        if name:
    
