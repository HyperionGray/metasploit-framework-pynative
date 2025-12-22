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
    
    def _extract_name(self, node: RubyASTNode) -> str:
        """Extract name from a Ruby AST node"""
        if node is None:
            return "unknown"
        
        if node.value is not None:
            return str(node.value)
        
        if node.node_type == 'const' and node.children:
            return str(node.children[0].value) if node.children[0].value else "unknown"
        
        if node.children:
            for child in node.children:
                if child.value is not None:
                    return str(child.value)
        
        return "unknown"
    
    def _map_ruby_class_to_python(self, ruby_class: str) -> str:
        """Map Ruby class names to Python equivalents"""
        mapping = {
            'Object': 'object',
            'BasicObject': 'object',
            'Class': 'type',
            'Module': 'object',
            'String': 'str',
            'Integer': 'int',
            'Float': 'float',
            'Array': 'list',
            'Hash': 'dict',
            'TrueClass': 'bool',
            'FalseClass': 'bool',
            'NilClass': 'type(None)',
        }
        return mapping.get(ruby_class, ruby_class)
    
    # Basic conversion methods for common nodes
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
    
    # Placeholder methods for basic node types
    def _convert_var_ref(self, node: RubyASTNode) -> ast.Name:
        """Convert Ruby variable reference to Python name"""
        name = self._extract_name(node)
        if name:
            return ast.Name(id=name, ctx=ast.Load())
        return None
    
    def _convert_var_field(self, node: RubyASTNode) -> ast.Name:
        """Convert Ruby variable field to Python name"""
        name = self._extract_name(node)
        if name:
            return ast.Name(id=name, ctx=ast.Store())
        return None
    
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
    
    def _convert_int(self, node: RubyASTNode) -> ast.Constant:
        """Convert Ruby integer to Python constant"""
        try:
            value = int(node.value) if node.value is not None else 0
            return ast.Constant(value=value)
        except (ValueError, TypeError):
            return ast.Constant(value=0)
    
    def _convert_float(self, node: RubyASTNode) -> ast.Constant:
        """Convert Ruby float to Python constant"""
        try:
            value = float(node.value) if node.value is not None else 0.0
            return ast.Constant(value=value)
        except (ValueError, TypeError):
            return ast.Constant(value=0.0)
    
    def _convert_string_literal(self, node: RubyASTNode) -> ast.Constant:
        """Convert Ruby string literal to Python constant"""
        if node.children:
            # Extract string content from children
            content = ""
            for child in node.children:
                if child.node_type == 'tstring_content' and child.value:
                    content += str(child.value)
            return ast.Constant(value=content)
        return ast.Constant(value="")
    
    def _convert_tstring_content(self, node: RubyASTNode) -> ast.Constant:
        """Convert Ruby string content to Python constant"""
        value = str(node.value) if node.value is not None else ""
        return ast.Constant(value=value)
    
    # Placeholder methods for other node types - these provide basic functionality
    def _convert_call(self, node: RubyASTNode) -> ast.Call:
        """Convert Ruby method call to Python function call"""
        return ast.Call(
            func=ast.Name(id="unknown_method", ctx=ast.Load()),
            args=[],
            keywords=[]
        )
    
    def _convert_method_add_arg(self, node: RubyASTNode) -> ast.Call:
        """Convert Ruby method call with arguments"""
        return self._convert_call(node)
    
    def _convert_const(self, node: RubyASTNode) -> ast.Name:
        """Convert Ruby constant to Python name"""
        name = self._extract_name(node)
        return ast.Name(id=name, ctx=ast.Load())
    
    def _convert_const_ref(self, node: RubyASTNode) -> ast.Name:
        """Convert Ruby constant reference to Python name"""
        return self._convert_const(node)
    
    def _convert_hash(self, node: RubyASTNode) -> ast.Dict:
        """Convert Ruby hash to Python dict"""
        return ast.Dict(keys=[], values=[])
    
    def _convert_assoc_new(self, node: RubyASTNode) -> tuple:
        """Convert Ruby hash association to Python dict key-value pair"""
        return (ast.Constant(value="key"), ast.Constant(value="value"))
    
    def _convert_array(self, node: RubyASTNode) -> ast.List:
        """Convert Ruby array to Python list"""
        return ast.List(elts=[], ctx=ast.Load())
    
    def _convert_string_content(self, node: RubyASTNode) -> ast.Constant:
        """Convert Ruby string content to Python constant"""
        return ast.Constant(value="")
    
    def _convert_symbol_literal(self, node: RubyASTNode) -> ast.Constant:
        """Convert Ruby symbol literal to Python string constant"""
        return ast.Constant(value="symbol")
    
    def _convert_symbol(self, node: RubyASTNode) -> ast.Constant:
        """Convert Ruby symbol to Python string constant"""
        name = self._extract_name(node)
        return ast.Constant(value=name)
    
    def _convert_if(self, node: RubyASTNode) -> ast.If:
        """Convert Ruby if statement to Python if statement"""
        return ast.If(
            test=ast.Constant(value=True),
            body=[ast.Pass()],
            orelse=[]
        )
    
    def _convert_unless(self, node: RubyASTNode) -> ast.If:
        """Convert Ruby unless statement to Python if not statement"""
        return ast.If(
            test=ast.UnaryOp(op=ast.Not(), operand=ast.Constant(value=True)),
            body=[ast.Pass()],
            orelse=[]
        )
    
    def _convert_while(self, node: RubyASTNode) -> ast.While:
        """Convert Ruby while loop to Python while loop"""
        return ast.While(
            test=ast.Constant(value=True),
            body=[ast.Pass()],
            orelse=[]
        )
    
    def _convert_for(self, node: RubyASTNode) -> ast.For:
        """Convert Ruby for loop to Python for loop"""
        return ast.For(
            target=ast.Name(id="item", ctx=ast.Store()),
            iter=ast.Name(id="iterable", ctx=ast.Load()),
            body=[ast.Pass()],
            orelse=[]
        )
    
    def _convert_return(self, node: RubyASTNode) -> ast.Return:
        """Convert Ruby return statement to Python return statement"""
        return ast.Return(value=ast.Constant(value=None))
    
    def _convert_yield(self, node: RubyASTNode) -> ast.Expr:
        """Convert Ruby yield to Python expression (placeholder)"""
        return ast.Expr(value=ast.Constant(value="# TODO: Convert yield"))
    
    def _convert_binary(self, node: RubyASTNode) -> ast.BinOp:
        """Convert Ruby binary operation to Python binary operation"""
        return ast.BinOp(
            left=ast.Constant(value=0),
            op=ast.Add(),
            right=ast.Constant(value=0)
        )
    
    def _convert_unary(self, node: RubyASTNode) -> ast.UnaryOp:
        """Convert Ruby unary operation to Python unary operation"""
        return ast.UnaryOp(op=ast.UAdd(), operand=ast.Constant(value=0))
    
    def _convert_paren(self, node: RubyASTNode) -> ast.AST:
        """Convert Ruby parentheses to Python expression"""
        if node.children:
            return self._convert_node(node.children[0])
        return ast.Constant(value=None)
    
    def _convert_rational(self, node: RubyASTNode) -> ast.Constant:
        """Convert Ruby rational to Python float"""
        return ast.Constant(value=0.0)
    
    def _convert_imaginary(self, node: RubyASTNode) -> ast.Constant:
        """Convert Ruby imaginary number to Python complex"""
        return ast.Constant(value=0j)
    
    def _convert_kw(self, node: RubyASTNode) -> ast.Constant:
        """Convert Ruby keyword to Python constant"""
        keyword = str(node.value) if node.value else "nil"
        if keyword == "nil":
            return ast.Constant(value=None)
        elif keyword == "true":
            return ast.Constant(value=True)
        elif keyword == "false":
            return ast.Constant(value=False)
        else:
            return ast.Constant(value=keyword)
    
    def _convert_regexp_literal(self, node: RubyASTNode) -> ast.Call:
        """Convert Ruby regexp literal to Python re.compile call"""
        return ast.Call(
            func=ast.Attribute(
                value=ast.Name(id="re", ctx=ast.Load()),
                attr="compile",
                ctx=ast.Load()
            ),
            args=[ast.Constant(value=".*")],
            keywords=[]
        )
    
    def _convert_literal(self, node: RubyASTNode) -> ast.Constant:
        """Convert Ruby literal to Python constant"""
        return ast.Constant(value=node.value)
    
    def _convert_block_var(self, node: RubyASTNode) -> ast.AST:
        """Convert Ruby block variable to Python expression"""
        return ast.Constant(value="# TODO: Convert block_var")
    
    def _convert_brace_block(self, node: RubyASTNode) -> ast.AST:
        """Convert Ruby brace block to Python expression"""
        return ast.Constant(value="# TODO: Convert brace_block")
    
    def _convert_do_block(self, node: RubyASTNode) -> ast.AST:
        """Convert Ruby do block to Python expression"""
        return ast.Constant(value="# TODO: Convert do_block")


def main():
    """Test the Python AST generator"""
    import argparse
    from ruby_ast_parser import RubyASTParser
    
    parser = argparse.ArgumentParser(description="Convert Ruby code to Python")
    parser.add_argument('file', nargs='?', help='Ruby file to convert')
    parser.add_argument('--code', help='Ruby code string to convert')
    
    args = parser.parse_args()
    
    ruby_parser = RubyASTParser()
    python_generator = PythonASTGenerator()
    
    try:
        if args.file:
            ruby_ast = ruby_parser.parse_ruby_file(args.file)
        elif args.code:
            ruby_ast = ruby_parser.parse_ruby_code(args.code)
        else:
            # Read from stdin
            import sys
            code = sys.stdin.read()
            ruby_ast = ruby_parser.parse_ruby_code(code)
        
        python_code = python_generator.generate_python_code(ruby_ast)
        print("Generated Python code:")
        print("=" * 40)
        print(python_code)
        
    except Exception as e:
        print(f"Error: {e}")
        return 1
    
    return 0


if __name__ == '__main__':
    exit(main())