#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
AST-Based Ruby to Python Transpiler

This module translates Ruby Abstract Syntax Trees (AST) to Python ASTs,
providing a proper syntax tree to syntax tree conversion rather than
using heuristics or regular expressions.

The translation process:
1. Ruby source → Ruby AST (via ruby_ast_extractor.rb)
2. Ruby AST → Python AST (via this module)
3. Python AST → Python source (via ast.unparse)
"""

import ast
import json
import subprocess
import sys
from pathlib import Path
from typing import Any, Dict, List, Optional, Union
from dataclasses import dataclass


@dataclass
class TranslationContext:
    """Context information for AST translation"""
    in_class: bool = False
    in_method: bool = False
    current_class: Optional[str] = None
    current_method: Optional[str] = None
    indent_level: int = 0


class RubyASTTranslator:
    """
    Translates Ruby AST nodes to Python AST nodes.
    
    This provides a proper AST-to-AST translation that preserves
    semantic meaning and structure, rather than using regex heuristics.
    """
    
    def __init__(self):
        self.context = TranslationContext()
        self.ruby_to_python_operators = {
            '+': ast.Add(),
            '-': ast.Sub(),
            '*': ast.Mult(),
            '/': ast.Div(),
            '//': ast.FloorDiv(),
            '%': ast.Mod(),
            '**': ast.Pow(),
            '<<': ast.LShift(),
            '>>': ast.RShift(),
            '|': ast.BitOr(),
            '^': ast.BitXor(),
            '&': ast.BitAnd(),
            '&&': ast.And(),
            '||': ast.Or(),
            '==': ast.Eq(),
            '!=': ast.NotEq(),
            '<': ast.Lt(),
            '<=': ast.LtE(),
            '>': ast.Gt(),
            '>=': ast.GtE(),
            '!': ast.Not(),
            '~': ast.Invert(),
            '-@': ast.USub(),
            '+@': ast.UAdd(),
        }
    
    def translate(self, ruby_ast: Dict[str, Any]) -> ast.Module:
        """
        Translate a Ruby AST to a Python AST.
        
        Args:
            ruby_ast: Ruby AST as a dictionary (from JSON)
            
        Returns:
            Python AST Module node
        """
        if not ruby_ast or ruby_ast.get('type') != 'Program':
            raise ValueError("Invalid Ruby AST: must be a Program node")
        
        body = ruby_ast.get('body', [])
        if not isinstance(body, list):
            body = [body]
        
        py_body = []
        for node in body:
            if node:
                translated = self._translate_node(node)
                if translated is not None:
                    if isinstance(translated, list):
                        py_body.extend(translated)
                    else:
                        py_body.append(translated)
        
        return ast.Module(body=py_body, type_ignores=[])
    
    def _translate_node(self, node: Union[Dict, Any]) -> Optional[Union[ast.AST, List[ast.AST]]]:
        """
        Translate a single Ruby AST node to Python AST node(s).
        
        Args:
            node: Ruby AST node (dictionary or primitive)
            
        Returns:
            Python AST node(s) or None
        """
        if node is None:
            return None
        
        # Handle primitives
        if not isinstance(node, dict):
            return None
        
        node_type = node.get('type')
        if not node_type:
            return None
        
        # Dispatch to appropriate handler
        handler_name = f'_translate_{node_type.lower()}'
        handler = getattr(self, handler_name, None)
        
        if handler:
            return handler(node)
        else:
            # Unknown node type - log warning and skip
            print(f"Warning: Unknown Ruby AST node type: {node_type}", file=sys.stderr)
            return None
    
    def _translate_classdefinition(self, node: Dict) -> ast.ClassDef:
        """Translate Ruby ClassDefinition to Python ClassDef"""
        # Extract class name
        name_node = node.get('name', {})
        class_name = self._extract_constant_name(name_node)
        
        # Extract superclass
        bases = []
        superclass_node = node.get('superclass')
        if superclass_node:
            superclass_name = self._extract_constant_name(superclass_node)
            if superclass_name:
                bases.append(ast.Name(id=superclass_name, ctx=ast.Load()))
        
        # Translate body
        body_node = node.get('body', {})
        body_statements = body_node.get('body', []) if isinstance(body_node, dict) else []
        if not isinstance(body_statements, list):
            body_statements = [body_statements] if body_statements else []
        
        old_context = (self.context.in_class, self.context.current_class)
        self.context.in_class = True
        self.context.current_class = class_name
        
        py_body = []
        for stmt in body_statements:
            if stmt:
                translated = self._translate_node(stmt)
                if translated:
                    if isinstance(translated, list):
                        py_body.extend(translated)
                    else:
                        py_body.append(translated)
        
        self.context.in_class, self.context.current_class = old_context
        
        # Add pass if body is empty
        if not py_body:
            py_body = [ast.Pass()]
        
        return ast.ClassDef(
            name=class_name,
            bases=bases,
            keywords=[],
            body=py_body,
            decorator_list=[]
        )
    
    def _translate_methoddefinition(self, node: Dict) -> ast.FunctionDef:
        """Translate Ruby MethodDefinition to Python FunctionDef"""
        # Extract method name
        name_node = node.get('name', {})
        method_name = name_node.get('value', 'unknown') if isinstance(name_node, dict) else str(name_node)
        
        # Extract parameters
        params_node = node.get('params', {})
        args = self._translate_parameters(params_node)
        
        # Add 'self' parameter if inside a class
        if self.context.in_class:
            args.args.insert(0, ast.arg(arg='self', annotation=None))
        
        # Translate body
        body_node = node.get('body', {})
        body_statements = body_node.get('body', []) if isinstance(body_node, dict) else []
        if not isinstance(body_statements, list):
            body_statements = [body_statements] if body_statements else []
        
        old_context = (self.context.in_method, self.context.current_method)
        self.context.in_method = True
        self.context.current_method = method_name
        
        py_body = []
        for stmt in body_statements:
            if stmt:
                translated = self._translate_node(stmt)
                if translated:
                    if isinstance(translated, list):
                        py_body.extend(translated)
                    else:
                        py_body.append(translated)
        
        self.context.in_method, self.context.current_method = old_context
        
        # Add pass if body is empty
        if not py_body:
            py_body = [ast.Pass()]
        
        return ast.FunctionDef(
            name=method_name,
            args=args,
            body=py_body,
            decorator_list=[],
            returns=None
        )
    
    def _translate_parameters(self, params_node: Dict) -> ast.arguments:
        """Translate Ruby Parameters to Python arguments"""
        if not params_node or not isinstance(params_node, dict):
            return ast.arguments(
                posonlyargs=[],
                args=[],
                vararg=None,
                kwonlyargs=[],
                kw_defaults=[],
                kwarg=None,
                defaults=[]
            )
        
        # Required parameters
        required = params_node.get('required', []) or []
        args = []
        for param in required:
            if param:
                param_name = self._extract_identifier(param)
                if param_name:
                    args.append(ast.arg(arg=param_name, annotation=None))
        
        # Optional parameters (with defaults)
        optional = params_node.get('optional', []) or []
        defaults = []
        for opt_pair in optional:
            if opt_pair and isinstance(opt_pair, list) and len(opt_pair) >= 2:
                param_name = self._extract_identifier(opt_pair[0])
                default_value = self._translate_node(opt_pair[1])
                if param_name:
                    args.append(ast.arg(arg=param_name, annotation=None))
                    defaults.append(default_value if default_value else ast.Constant(value=None))
        
        # Rest parameter (*args)
        rest = params_node.get('rest')
        vararg = None
        if rest:
            rest_name = self._extract_identifier(rest)
            if rest_name:
                vararg = ast.arg(arg=rest_name, annotation=None)
        
        # Block parameter (&block)
        block = params_node.get('block')
        kwarg = None
        if block:
            block_name = self._extract_identifier(block)
            if block_name:
                kwarg = ast.arg(arg=block_name, annotation=None)
        
        return ast.arguments(
            posonlyargs=[],
            args=args,
            vararg=vararg,
            kwonlyargs=[],
            kw_defaults=[],
            kwarg=kwarg,
            defaults=defaults
        )
    
    def _translate_command(self, node: Dict) -> ast.Expr:
        """Translate Ruby Command (function call without parens) to Python Call"""
        name_node = node.get('name', {})
        func_name = name_node.get('value', 'unknown') if isinstance(name_node, dict) else str(name_node)
        
        # Translate arguments
        args_node = node.get('args', {})
        args = []
        if args_node:
            args_list = args_node.get('args', []) if isinstance(args_node, dict) else []
            if not isinstance(args_list, list):
                args_list = [args_list] if args_list else []
            for arg in args_list:
                if arg:
                    translated_arg = self._translate_node(arg)
                    if translated_arg:
                        args.append(translated_arg)
        
        # Special handling for common Ruby methods
        if func_name == 'puts':
            func_name = 'print'
        elif func_name == 'require':
            # Convert require to import
            if args and isinstance(args[0], ast.Constant):
                module_name = args[0].value
                return ast.Import(names=[ast.alias(name=module_name, asname=None)])
        
        call = ast.Call(
            func=ast.Name(id=func_name, ctx=ast.Load()),
            args=args,
            keywords=[]
        )
        
        return ast.Expr(value=call)
    
    def _translate_stringliteral(self, node: Dict) -> ast.Constant:
        """Translate Ruby StringLiteral to Python Constant"""
        parts_node = node.get('parts', {})
        
        # Simple string without interpolation
        if isinstance(parts_node, dict):
            parts_list = parts_node.get('parts', [])
            if isinstance(parts_list, list) and len(parts_list) == 1:
                part = parts_list[0]
                if isinstance(part, dict) and part.get('type') == 'StringContent':
                    value = part.get('value', '')
                    return ast.Constant(value=value)
        
        # String with interpolation - convert to f-string (JoinedStr)
        # For now, simplify to regular string
        # TODO: Implement proper f-string conversion
        return ast.Constant(value='')
    
    def _translate_integer(self, node: Dict) -> ast.Constant:
        """Translate Ruby Integer to Python Constant"""
        value = node.get('value', 0)
        return ast.Constant(value=int(value))
    
    def _translate_float(self, node: Dict) -> ast.Constant:
        """Translate Ruby Float to Python Constant"""
        value = node.get('value', 0.0)
        return ast.Constant(value=float(value))
    
    def _translate_symbolliteral(self, node: Dict) -> ast.Constant:
        """Translate Ruby Symbol to Python string constant"""
        value_node = node.get('value', {})
        if isinstance(value_node, dict):
            symbol_node = value_node.get('value')
            if isinstance(symbol_node, dict):
                symbol_value = symbol_node.get('value', '')
            else:
                symbol_value = str(symbol_node)
        else:
            symbol_value = str(value_node)
        return ast.Constant(value=symbol_value)
    
    def _translate_hash(self, node: Dict) -> ast.Dict:
        """Translate Ruby Hash to Python Dict"""
        pairs_node = node.get('pairs', {})
        pairs_list = pairs_node.get('pairs', []) if isinstance(pairs_node, dict) else []
        
        keys = []
        values = []
        for pair in pairs_list:
            if pair and isinstance(pair, dict) and pair.get('type') == 'Association':
                key = self._translate_node(pair.get('key'))
                value = self._translate_node(pair.get('value'))
                if key and value:
                    keys.append(key)
                    values.append(value)
        
        return ast.Dict(keys=keys, values=values)
    
    def _translate_array(self, node: Dict) -> ast.List:
        """Translate Ruby Array to Python List"""
        elements_node = node.get('elements', [])
        if not isinstance(elements_node, list):
            elements_node = [elements_node] if elements_node else []
        
        elts = []
        for elem in elements_node:
            if elem:
                translated = self._translate_node(elem)
                if translated:
                    elts.append(translated)
        
        return ast.List(elts=elts, ctx=ast.Load())
    
    def _translate_binaryoperation(self, node: Dict) -> ast.BinOp:
        """Translate Ruby BinaryOperation to Python BinOp"""
        left = self._translate_node(node.get('left'))
        right = self._translate_node(node.get('right'))
        operator_str = node.get('operator', '+')
        
        op = self.ruby_to_python_operators.get(operator_str, ast.Add())
        
        return ast.BinOp(left=left, op=op, right=right)
    
    def _translate_ifstatement(self, node: Dict) -> ast.If:
        """Translate Ruby IfStatement to Python If"""
        test = self._translate_node(node.get('condition'))
        
        then_clause = node.get('then_clause')
        body = self._translate_body(then_clause)
        
        else_clause = node.get('else_clause')
        orelse = self._translate_body(else_clause) if else_clause else []
        
        return ast.If(test=test, body=body, orelse=orelse)
    
    def _translate_unlessstatement(self, node: Dict) -> ast.If:
        """Translate Ruby UnlessStatement to Python If with negated condition"""
        condition = self._translate_node(node.get('condition'))
        test = ast.UnaryOp(op=ast.Not(), operand=condition)
        
        then_clause = node.get('then_clause')
        body = self._translate_body(then_clause)
        
        else_clause = node.get('else_clause')
        orelse = self._translate_body(else_clause) if else_clause else []
        
        return ast.If(test=test, body=body, orelse=orelse)
    
    def _translate_returnstatement(self, node: Dict) -> ast.Return:
        """Translate Ruby ReturnStatement to Python Return"""
        value = self._translate_node(node.get('value'))
        return ast.Return(value=value)
    
    def _translate_constantreference(self, node: Dict) -> ast.Name:
        """Translate Ruby ConstantReference to Python Name"""
        name = self._extract_constant_name(node)
        return ast.Name(id=name, ctx=ast.Load())
    
    def _translate_variablereference(self, node: Dict) -> ast.Name:
        """Translate Ruby VariableReference to Python Name"""
        name_node = node.get('name', {})
        if isinstance(name_node, dict):
            var_name = name_node.get('value', 'unknown')
        else:
            var_name = str(name_node)
        return ast.Name(id=var_name, ctx=ast.Load())
    
    def _translate_identifier(self, node: Dict) -> ast.Name:
        """Translate Ruby Identifier to Python Name"""
        if isinstance(node, dict):
            var_name = node.get('value', 'unknown')
        else:
            var_name = str(node)
        return ast.Name(id=var_name, ctx=ast.Load())
    
    def _translate_assignment(self, node: Dict) -> ast.Assign:
        """Translate Ruby Assignment to Python Assign"""
        target = self._translate_node(node.get('target'))
        value = self._translate_node(node.get('value'))
        
        # Ensure target has Store context
        if isinstance(target, ast.Name):
            target.ctx = ast.Store()
        
        return ast.Assign(targets=[target], value=value)
    
    # Helper methods
    
    def _extract_constant_name(self, node: Dict) -> str:
        """Extract constant name from a ConstantReference node"""
        if not isinstance(node, dict):
            return 'Unknown'
        
        node_type = node.get('type')
        if node_type == 'ConstantReference':
            name_node = node.get('name', {})
            if isinstance(name_node, dict):
                return name_node.get('value', 'Unknown')
        elif node_type == 'Constant':
            return node.get('value', 'Unknown')
        elif node_type == 'ConstantPathReference':
            # Handle Foo::Bar::Baz
            parent = self._extract_constant_name(node.get('parent', {}))
            name = self._extract_constant_name(node.get('name', {}))
            return f"{parent}.{name}" if parent and name else name
        
        return 'Unknown'
    
    def _extract_identifier(self, node: Any) -> Optional[str]:
        """Extract identifier name from a node"""
        if not isinstance(node, dict):
            return None
        
        node_type = node.get('type')
        if node_type == 'Identifier':
            return node.get('value')
        elif node_type == 'VariableReference':
            name_node = node.get('name', {})
            if isinstance(name_node, dict):
                return name_node.get('value')
        
        return None
    
    def _translate_body(self, body_node: Any) -> List[ast.stmt]:
        """Translate a body node (can be various types) to list of statements"""
        if not body_node:
            return [ast.Pass()]
        
        if isinstance(body_node, dict):
            body_type = body_node.get('type')
            if body_type == 'BodyStatement':
                statements = body_node.get('body', [])
            else:
                statements = [body_node]
        elif isinstance(body_node, list):
            statements = body_node
        else:
            return [ast.Pass()]
        
        if not isinstance(statements, list):
            statements = [statements]
        
        result = []
        for stmt in statements:
            if stmt:
                translated = self._translate_node(stmt)
                if translated:
                    if isinstance(translated, list):
                        result.extend(translated)
                    else:
                        result.append(translated)
        
        return result if result else [ast.Pass()]


class ASTTranspiler:
    """
    Main transpiler class that orchestrates the Ruby to Python conversion.
    """
    
    def __init__(self, ruby_extractor_path: Optional[Path] = None):
        """
        Initialize the transpiler.
        
        Args:
            ruby_extractor_path: Path to ruby_ast_extractor.rb script
        """
        if ruby_extractor_path is None:
            # Default to the script in the same directory
            ruby_extractor_path = Path(__file__).parent / 'ruby_ast_extractor.rb'
        
        self.ruby_extractor_path = ruby_extractor_path
        self.translator = RubyASTTranslator()
    
    def transpile_file(self, ruby_file: Path) -> str:
        """
        Transpile a Ruby file to Python code.
        
        Args:
            ruby_file: Path to Ruby source file
            
        Returns:
            Python source code as string
        """
        # Extract Ruby AST
        ruby_ast = self._extract_ruby_ast(ruby_file)
        
        # Translate to Python AST
        python_ast = self.translator.translate(ruby_ast)
        
        # Fix missing location information (line numbers, etc.)
        ast.fix_missing_locations(python_ast)
        
        # Generate Python code
        python_code = ast.unparse(python_ast)
        
        return python_code
    
    def transpile_code(self, ruby_code: str) -> str:
        """
        Transpile Ruby code string to Python code.
        
        Args:
            ruby_code: Ruby source code as string
            
        Returns:
            Python source code as string
        """
        # Extract Ruby AST
        ruby_ast = self._extract_ruby_ast_from_code(ruby_code)
        
        # Translate to Python AST
        python_ast = self.translator.translate(ruby_ast)
        
        # Fix missing location information (line numbers, etc.)
        ast.fix_missing_locations(python_ast)
        
        # Generate Python code
        python_code = ast.unparse(python_ast)
        
        return python_code
    
    def _extract_ruby_ast(self, ruby_file: Path) -> Dict[str, Any]:
        """Extract Ruby AST from a file"""
        result = subprocess.run(
            ['ruby', str(self.ruby_extractor_path), str(ruby_file)],
            capture_output=True,
            text=True,
            check=True
        )
        
        return json.loads(result.stdout)
    
    def _extract_ruby_ast_from_code(self, ruby_code: str) -> Dict[str, Any]:
        """Extract Ruby AST from code string"""
        result = subprocess.run(
            ['ruby', str(self.ruby_extractor_path), '-e', ruby_code],
            capture_output=True,
            text=True,
            check=True
        )
        
        return json.loads(result.stdout)


def main():
    """Main entry point for command-line usage"""
    import argparse
    
    parser = argparse.ArgumentParser(
        description='AST-based Ruby to Python transpiler',
        formatter_class=argparse.RawDescriptionHelpFormatter
    )
    parser.add_argument('input', help='Ruby source file or code (with -e)')
    parser.add_argument('-e', '--eval', action='store_true',
                       help='Treat input as Ruby code string')
    parser.add_argument('-o', '--output', help='Output Python file (default: stdout)')
    parser.add_argument('--ast', action='store_true',
                       help='Output Python AST instead of code')
    
    args = parser.parse_args()
    
    transpiler = ASTTranspiler()
    
    try:
        if args.eval:
            python_code = transpiler.transpile_code(args.input)
        else:
            ruby_file = Path(args.input)
            if not ruby_file.exists():
                print(f"Error: File not found: {ruby_file}", file=sys.stderr)
                sys.exit(1)
            python_code = transpiler.transpile_file(ruby_file)
        
        if args.output:
            Path(args.output).write_text(python_code)
            print(f"Transpiled code written to: {args.output}")
        else:
            print(python_code)
    
    except subprocess.CalledProcessError as e:
        print(f"Error extracting Ruby AST: {e.stderr}", file=sys.stderr)
        sys.exit(1)
    except Exception as e:
        print(f"Error during transpilation: {e}", file=sys.stderr)
        import traceback
        traceback.print_exc()
        sys.exit(1)


if __name__ == '__main__':
    main()
