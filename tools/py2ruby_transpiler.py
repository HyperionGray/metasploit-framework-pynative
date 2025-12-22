#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
Python to Ruby Transpiler

A full transpiler that converts Python code to Ruby, including:
- Syntax translation
- Control flow conversion
- Data structure mapping
- Function/method conversion
- Class definitions
- Module imports
- Exception handling
- Common library mappings

Author: Metasploit Framework Python Migration Team
License: BSD-3-Clause
"""

import ast
import sys
import argparse
from pathlib import Path
from typing import Dict, List, Optional, Set, Any
import re


class PythonToRubyTranspiler(ast.NodeVisitor):
    """
    Full AST-based Python to Ruby transpiler.
    
    Converts Python source code to idiomatic Ruby by traversing
    the Python AST and generating equivalent Ruby constructs.
    """
    
    def __init__(self):
        self.output = []
        self.indent_level = 0
        self.indent_string = "  "
        self.imports = []
        self.in_class = False
        self.in_function = False
        self.class_name = None
        
        # Python stdlib to Ruby mappings
        self.module_mappings = {
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
        self.method_mappings = {
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
    
    def get_ruby_code(self) -> str:
        """Get the generated Ruby code."""
        return "\n".join(self.output)
    
    def visit_Module(self, node: ast.Module):
        """Visit module (top-level)."""
        self.write("#!/usr/bin/env ruby")
        self.write("# -*- coding: utf-8 -*-")
        self.write("")
        self.write("# Transpiled from Python to Ruby")
        self.write("")
        
        # Process all statements
        for stmt in node.body:
            self.visit(stmt)
    
    def visit_Import(self, node: ast.Import):
        """Visit import statement: import x, y, z"""
        for alias in node.names:
            module_name = alias.name
            ruby_module = self.module_mappings.get(module_name, module_name)
            
            if ruby_module:
                if alias.asname:
                    self.write(f"require '{ruby_module.lower()}'")
                    self.write(f"{alias.asname} = {ruby_module}")
                else:
                    self.write(f"require '{ruby_module.lower()}'")
    
    def visit_ImportFrom(self, node: ast.ImportFrom):
        """Visit from x import y statement."""
        module = node.module or ""
        ruby_module = self.module_mappings.get(module, module)
        
        if ruby_module:
            self.write(f"require '{ruby_module.lower()}'")
    
    def visit_FunctionDef(self, node: ast.FunctionDef):
        """Visit function definition."""
        self.in_function = True
        
        # Function name
        func_name = node.name
        
        # Handle special methods
        if self.in_class:
            if func_name == '__init__':
                func_name = 'initialize'
            elif func_name == '__str__':
                func_name = 'to_s'
            elif func_name == '__repr__':
                func_name = 'inspect'
            elif func_name == '__len__':
                func_name = 'length'
            elif func_name == '__eq__':
                func_name = '=='
            elif func_name.startswith('__') and func_name.endswith('__'):
                # Other dunder methods - keep as-is with warning
                self.write(f"# WARNING: Python magic method {func_name} may need manual conversion")
        
        # Function arguments
        args = []
        defaults_offset = len(node.args.args) - len(node.args.defaults)
        
        for i, arg in enumerate(node.args.args):
            arg_name = arg.arg
            if arg_name == 'self':
                continue  # Skip self in Ruby
            
            # Check for default values
            default_idx = i - defaults_offset
            if default_idx >= 0:
                default_val = self.visit_expr(node.args.defaults[default_idx])
                args.append(f"{arg_name} = {default_val}")
            else:
                args.append(arg_name)
        
        # *args and **kwargs
        if node.args.vararg:
            args.append(f"*{node.args.vararg.arg}")
        if node.args.kwarg:
            args.append(f"**{node.args.kwarg.arg}")
        
        args_str = ", ".join(args)
        
        # Write function definition
        if args_str:
            self.write(f"def {func_name}({args_str})")
        else:
            self.write(f"def {func_name}")
        
        self.indent()
        
        # Function body
        if node.body:
            for stmt in node.body:
                self.visit(stmt)
        else:
            self.write("# Empty function")
        
        self.dedent()
        self.write("end")
        self.write("")
        
        self.in_function = False
    
    def visit_ClassDef(self, node: ast.ClassDef):
        """Visit class definition."""
        self.in_class = True
        self.class_name = node.name
        
        # Base classes
        if node.bases:
            bases = [self.visit_expr(base) for base in node.bases]
            base_str = " < " + ", ".join(bases)
        else:
            base_str = ""
        
        self.write(f"class {node.name}{base_str}")
        self.indent()
        
        # Class body
        for stmt in node.body:
            self.visit(stmt)
        
        self.dedent()
        self.write("end")
        self.write("")
        
        self.in_class = False
        self.class_name = None
    
    def visit_Return(self, node: ast.Return):
        """Visit return statement."""
        if node.value:
            value = self.visit_expr(node.value)
            self.write(f"return {value}")
        else:
            self.write("return")
    
    def visit_Assign(self, node: ast.Assign):
        """Visit assignment: x = value"""
        value = self.visit_expr(node.value)
        
        for target in node.targets:
            target_str = self.visit_expr(target)
            self.write(f"{target_str} = {value}")
    
    def visit_AugAssign(self, node: ast.AugAssign):
        """Visit augmented assignment: x += 1"""
        target = self.visit_expr(node.target)
        op = self.visit_operator(node.op)
        value = self.visit_expr(node.value)
        self.write(f"{target} {op}= {value}")
    
    def visit_If(self, node: ast.If):
        """Visit if statement."""
        test = self.visit_expr(node.test)
        self.write(f"if {test}")
        self.indent()
        
        for stmt in node.body:
            self.visit(stmt)
        
        self.dedent()
        
        if node.orelse:
            if len(node.orelse) == 1 and isinstance(node.orelse[0], ast.If):
                # elif
                self.write("else")
                self.visit(node.orelse[0])
                return
            else:
                self.write("else")
                self.indent()
                for stmt in node.orelse:
                    self.visit(stmt)
                self.dedent()
        
        self.write("end")
    
    def visit_While(self, node: ast.While):
        """Visit while loop."""
        test = self.visit_expr(node.test)
        self.write(f"while {test}")
        self.indent()
        
        for stmt in node.body:
            self.visit(stmt)
        
        self.dedent()
        self.write("end")
    
    def visit_For(self, node: ast.For):
        """Visit for loop."""
        target = self.visit_expr(node.target)
        iter_expr = self.visit_expr(node.iter)
        
        # Check if it's a range
        if isinstance(node.iter, ast.Call) and isinstance(node.iter.func, ast.Name):
            if node.iter.func.id == 'range':
                # Convert range to Ruby range
                args = [self.visit_expr(arg) for arg in node.iter.args]
                if len(args) == 1:
                    range_expr = f"(0...{args[0]})"
                elif len(args) == 2:
                    range_expr = f"({args[0]}...{args[1]})"
                elif len(args) == 3:
                    # Ruby doesn't have step in range, use step method
                    self.write(f"({args[0]}...{args[1]}).step({args[2]}) do |{target}|")
                    self.indent()
                    for stmt in node.body:
                        self.visit(stmt)
                    self.dedent()
                    self.write("end")
                    return
                else:
                    range_expr = iter_expr
                
                self.write(f"{range_expr}.each do |{target}|")
            else:
                self.write(f"{iter_expr}.each do |{target}|")
        else:
            self.write(f"{iter_expr}.each do |{target}|")
        
        self.indent()
        
        for stmt in node.body:
            self.visit(stmt)
        
        self.dedent()
        self.write("end")
    
    def visit_With(self, node: ast.With):
        """Visit with statement (context manager)."""
        # Ruby doesn't have exact equivalent, use begin/ensure
        for item in node.items:
            context = self.visit_expr(item.context_expr)
            var = self.visit_expr(item.optional_vars) if item.optional_vars else "_"
            self.write(f"{var} = {context}")
        
        self.write("begin")
        self.indent()
        
        for stmt in node.body:
            self.visit(stmt)
        
        self.dedent()
        self.write("ensure")
        self.indent()
        
        for item in node.items:
            var = self.visit_expr(item.optional_vars) if item.optional_vars else "_"
            self.write(f"{var}.close if {var}.respond_to?(:close)")
        
        self.dedent()
        self.write("end")
    
    def visit_Try(self, node: ast.Try):
        """Visit try/except statement."""
        self.write("begin")
        self.indent()
        
        for stmt in node.body:
            self.visit(stmt)
        
        self.dedent()
        
        # Exception handlers
        for handler in node.handlers:
            if handler.type:
                exc_type = self.visit_expr(handler.type)
                # Map Python exceptions to Ruby
                exc_type = self.map_exception(exc_type)
            else:
                exc_type = "StandardError"
            
            if handler.name:
                self.write(f"rescue {exc_type} => {handler.name}")
            else:
                self.write(f"rescue {exc_type}")
            
            self.indent()
            for stmt in handler.body:
                self.visit(stmt)
            self.dedent()
        
        # Else clause
        if node.orelse:
            self.write("else")
            self.indent()
            for stmt in node.orelse:
                self.visit(stmt)
            self.dedent()
        
        # Finally clause
        if node.finalbody:
            self.write("ensure")
            self.indent()
            for stmt in node.finalbody:
                self.visit(stmt)
            self.dedent()
        
        self.write("end")
    
    def visit_Raise(self, node: ast.Raise):
        """Visit raise statement."""
        if node.exc:
            exc = self.visit_expr(node.exc)
            self.write(f"raise {exc}")
        else:
            self.write("raise")
    
    def visit_Expr(self, node: ast.Expr):
        """Visit expression statement."""
        expr = self.visit_expr(node.value)
        self.write(expr)
    
    def visit_Pass(self, node: ast.Pass):
        """Visit pass statement."""
        self.write("# pass")
    
    def visit_Break(self, node: ast.Break):
        """Visit break statement."""
        self.write("break")
    
    def visit_Continue(self, node: ast.Continue):
        """Visit continue statement."""
        self.write("next")
    
    def visit_expr(self, node) -> str:
        """Visit an expression node and return Ruby code string."""
        if node is None:
            return "nil"
        
        if isinstance(node, ast.Constant):
            return self.visit_Constant(node)
        elif isinstance(node, ast.Name):
            return self.visit_Name(node)
        elif isinstance(node, ast.Attribute):
            return self.visit_Attribute(node)
        elif isinstance(node, ast.Call):
            return self.visit_Call(node)
        elif isinstance(node, ast.BinOp):
            return self.visit_BinOp(node)
        elif isinstance(node, ast.UnaryOp):
            return self.visit_UnaryOp(node)
        elif isinstance(node, ast.Compare):
            return self.visit_Compare(node)
        elif isinstance(node, ast.BoolOp):
            return self.visit_BoolOp(node)
        elif isinstance(node, ast.List):
            return self.visit_List(node)
        elif isinstance(node, ast.Dict):
            return self.visit_Dict(node)
        elif isinstance(node, ast.Tuple):
            return self.visit_Tuple(node)
        elif isinstance(node, ast.Subscript):
            return self.visit_Subscript(node)
        elif isinstance(node, ast.IfExp):
            return self.visit_IfExp(node)
        elif isinstance(node, ast.Lambda):
            return self.visit_Lambda(node)
        elif isinstance(node, ast.ListComp):
            return self.visit_ListComp(node)
        elif isinstance(node, ast.DictComp):
            return self.visit_DictComp(node)
        elif isinstance(node, ast.JoinedStr):
            return self.visit_JoinedStr(node)
        else:
            return f"# TODO: Unsupported expression {type(node).__name__}"
    
    def visit_Constant(self, node: ast.Constant) -> str:
        """Visit constant value."""
        value = node.value
        
        if value is None:
            return "nil"
        elif value is True:
            return "true"
        elif value is False:
            return "false"
        elif isinstance(value, str):
            # Handle string escaping
            escaped = value.replace("\\", "\\\\").replace("'", "\\'")
            return f"'{escaped}'"
        elif isinstance(value, (int, float)):
            return str(value)
        else:
            return str(value)
    
    def visit_Name(self, node: ast.Name) -> str:
        """Visit name (variable)."""
        name = node.id
        
        # Convert Python keywords to Ruby
        if name == 'None':
            return 'nil'
        elif name == 'True':
            return 'true'
        elif name == 'False':
            return 'false'
        elif name == 'self':
            return 'self'
        else:
            return name
    
    def visit_Attribute(self, node: ast.Attribute) -> str:
        """Visit attribute access: obj.attr"""
        value = self.visit_expr(node.value)
        attr = node.attr
        
        # Map Python methods to Ruby
        attr = self.method_mappings.get(attr, attr)
        
        return f"{value}.{attr}"
    
    def visit_Call(self, node: ast.Call) -> str:
        """Visit function call."""
        func = self.visit_expr(node.func)
        
        # Handle built-in functions
        if isinstance(node.func, ast.Name):
            func_name = node.func.id
            
            # len(x) -> x.length
            if func_name == 'len':
                if node.args:
                    arg = self.visit_expr(node.args[0])
                    return f"{arg}.length"
            
            # print() -> puts
            elif func_name == 'print':
                args = [self.visit_expr(arg) for arg in node.args]
                return f"puts {', '.join(args)}"
            
            # str(), int(), float()
            elif func_name == 'str':
                if node.args:
                    arg = self.visit_expr(node.args[0])
                    return f"{arg}.to_s"
            elif func_name == 'int':
                if node.args:
                    arg = self.visit_expr(node.args[0])
                    return f"{arg}.to_i"
            elif func_name == 'float':
                if node.args:
                    arg = self.visit_expr(node.args[0])
                    return f"{arg}.to_f"
            
            # range()
            elif func_name == 'range':
                args = [self.visit_expr(arg) for arg in node.args]
                if len(args) == 1:
                    return f"(0...{args[0]})"
                elif len(args) == 2:
                    return f"({args[0]}...{args[1]})"
                elif len(args) == 3:
                    return f"({args[0]}...{args[1]}).step({args[2]})"
            
            # isinstance() -> is_a?
            elif func_name == 'isinstance':
                if len(node.args) >= 2:
                    obj = self.visit_expr(node.args[0])
                    cls = self.visit_expr(node.args[1])
                    return f"{obj}.is_a?({cls})"
            
            # hasattr() -> respond_to?
            elif func_name == 'hasattr':
                if len(node.args) >= 2:
                    obj = self.visit_expr(node.args[0])
                    attr = self.visit_expr(node.args[1])
                    return f"{obj}.respond_to?({attr})"
        
        # Regular function call
        args = [self.visit_expr(arg) for arg in node.args]
        
        # Handle keyword arguments
        for keyword in node.keywords:
            key = keyword.arg
            val = self.visit_expr(keyword.value)
            args.append(f"{key}: {val}")
        
        if args:
            return f"{func}({', '.join(args)})"
        else:
            return f"{func}()"
    
    def visit_BinOp(self, node: ast.BinOp) -> str:
        """Visit binary operation."""
        left = self.visit_expr(node.left)
        right = self.visit_expr(node.right)
        op = self.visit_operator(node.op)
        
        # Handle special cases
        if isinstance(node.op, ast.Pow):
            return f"{left} ** {right}"
        elif isinstance(node.op, ast.FloorDiv):
            return f"({left} / {right}).floor"
        elif isinstance(node.op, ast.Mod) and '%' in left:
            # String formatting
            return f"{left} % {right}"
        
        return f"{left} {op} {right}"
    
    def visit_UnaryOp(self, node: ast.UnaryOp) -> str:
        """Visit unary operation."""
        operand = self.visit_expr(node.operand)
        
        if isinstance(node.op, ast.Not):
            return f"!{operand}"
        elif isinstance(node.op, ast.USub):
            return f"-{operand}"
        elif isinstance(node.op, ast.UAdd):
            return f"+{operand}"
        else:
            return operand
    
    def visit_Compare(self, node: ast.Compare) -> str:
        """Visit comparison."""
        parts = []
        current_left = self.visit_expr(node.left)

        for op, comparator in zip(node.ops, node.comparators):
            right = self.visit_expr(comparator)
            if isinstance(op, ast.In):
                parts.append(f"{right}.include?({current_left})")
            elif isinstance(op, ast.NotIn):
                parts.append(f"!{right}.include?({current_left})")
            else:
                op_str = self.visit_comparison_op(op)
                parts.append(f"{current_left} {op_str} {right}")
            current_left = right
        
        return " && ".join(f"({part})" for part in parts)
    
    def visit_BoolOp(self, node: ast.BoolOp) -> str:
        """Visit boolean operation."""
        op = "&&" if isinstance(node.op, ast.And) else "||"
        values = [self.visit_expr(v) for v in node.values]
        return f"({' {} '.format(op).join(values)})"
    
    def visit_List(self, node: ast.List) -> str:
        """Visit list literal."""
        elements = [self.visit_expr(elt) for elt in node.elts]
        return f"[{', '.join(elements)}]"
    
    def visit_Dict(self, node: ast.Dict) -> str:
        """Visit dictionary literal."""
        pairs = []
        for key, value in zip(node.keys, node.values):
            k = self.visit_expr(key)
            v = self.visit_expr(value)
            # Ruby hash syntax
            if isinstance(key, ast.Constant) and isinstance(key.value, str):
                # Symbol key syntax
                pairs.append(f"{key.value}: {v}")
            else:
                pairs.append(f"{k} => {v}")
        return f"{{ {', '.join(pairs)} }}"
    
    def visit_Tuple(self, node: ast.Tuple) -> str:
        """Visit tuple (becomes array in Ruby)."""
        elements = [self.visit_expr(elt) for elt in node.elts]
        return f"[{', '.join(elements)}]"
    
    def visit_Subscript(self, node: ast.Subscript) -> str:
        """Visit subscript: obj[key]"""
        value = self.visit_expr(node.value)
        slice_val = self.visit_expr(node.slice)
        return f"{value}[{slice_val}]"
    
    def visit_IfExp(self, node: ast.IfExp) -> str:
        """Visit ternary expression: x if cond else y"""
        test = self.visit_expr(node.test)
        body = self.visit_expr(node.body)
        orelse = self.visit_expr(node.orelse)
        return f"({test} ? {body} : {orelse})"
    
    def visit_Lambda(self, node: ast.Lambda) -> str:
        """Visit lambda expression."""
        args = [arg.arg for arg in node.args.args]
        body = self.visit_expr(node.body)
        args_str = ", ".join(args)
        return f"lambda {{ |{args_str}| {body} }}"
    
    def visit_ListComp(self, node: ast.ListComp) -> str:
        """Visit list comprehension."""
        # [expr for target in iter if cond]
        # -> iter.select {|target| cond}.map {|target| expr}
        
        elt = self.visit_expr(node.elt)
        
        # Assume single generator for simplicity
        gen = node.generators[0]
        target = self.visit_expr(gen.target)
        iter_expr = self.visit_expr(gen.iter)
        
        if gen.ifs:
            # With filter(s)
            conditions = " && ".join(f"({self.visit_expr(if_cond)})" for if_cond in gen.ifs)
            return f"{iter_expr}.select {{ |{target}| {conditions} }}.map {{ |{target}| {elt} }}"
        else:
            # No filter
            return f"{iter_expr}.map {{ |{target}| {elt} }}"
    
    def visit_DictComp(self, node: ast.DictComp) -> str:
        """Visit dict comprehension."""
        key = self.visit_expr(node.key)
        value = self.visit_expr(node.value)
        
        gen = node.generators[0]
        target = self.visit_expr(gen.target)
        iter_expr = self.visit_expr(gen.iter)
        
        if gen.ifs:
            conditions = " && ".join(f"({self.visit_expr(if_cond)})" for if_cond in gen.ifs)
            return f"{iter_expr}.select {{ |{target}| {conditions} }}.map {{ |{target}| [{key}, {value}] }}.to_h"
        else:
            return f"{iter_expr}.map {{ |{target}| [{key}, {value}] }}.to_h"
    
    def visit_JoinedStr(self, node: ast.JoinedStr) -> str:
        """Visit f-string."""
        parts = []
        for value in node.values:
            if isinstance(value, ast.Constant):
                escaped_val = value.value.replace('\\', '\\\\').replace('"', '\\"')
                parts.append(escaped_val)
            elif isinstance(value, ast.FormattedValue):
                expr = self.visit_expr(value.value)
                parts.append(f"#{{{expr}}}")
        
        result = "".join(parts)
        return f'"{result}"'
    
    def visit_operator(self, op) -> str:
        """Convert Python operator to Ruby operator."""
        if isinstance(op, ast.Add):
            return "+"
        elif isinstance(op, ast.Sub):
            return "-"
        elif isinstance(op, ast.Mult):
            return "*"
        elif isinstance(op, ast.Div):
            return "/"
        elif isinstance(op, ast.FloorDiv):
            return "/"
        elif isinstance(op, ast.Mod):
            return "%"
        elif isinstance(op, ast.Pow):
            return "**"
        elif isinstance(op, ast.BitAnd):
            return "&"
        elif isinstance(op, ast.BitOr):
            return "|"
        elif isinstance(op, ast.BitXor):
            return "^"
        elif isinstance(op, ast.LShift):
            return "<<"
        elif isinstance(op, ast.RShift):
            return ">>"
        else:
            return "?"
    
    def visit_comparison_op(self, op) -> str:
        """Convert Python comparison operator to Ruby."""
        if isinstance(op, ast.Eq):
            return "=="
        elif isinstance(op, ast.NotEq):
            return "!="
        elif isinstance(op, ast.Lt):
            return "<"
        elif isinstance(op, ast.LtE):
            return "<="
        elif isinstance(op, ast.Gt):
            return ">"
        elif isinstance(op, ast.GtE):
            return ">="
        elif isinstance(op, ast.Is):
            return "=="
        elif isinstance(op, ast.IsNot):
            return "!="
        elif isinstance(op, ast.In):
            return "in"
        elif isinstance(op, ast.NotIn):
            return "not in"
        else:
            return "?"
    
    def map_exception(self, exc_type: str) -> str:
        """Map Python exception to Ruby exception."""
        exception_map = {
            'Exception': 'StandardError',
            'ValueError': 'ArgumentError',
            'TypeError': 'TypeError',
            'KeyError': 'KeyError',
            'IndexError': 'IndexError',
            'AttributeError': 'NoMethodError',
            'IOError': 'IOError',
            'OSError': 'SystemCallError',
            'RuntimeError': 'RuntimeError',
            'NotImplementedError': 'NotImplementedError',
            'ZeroDivisionError': 'ZeroDivisionError',
            'FileNotFoundError': 'Errno::ENOENT',
            'PermissionError': 'Errno::EACCES',
        }
        return exception_map.get(exc_type, exc_type)


def transpile_python_to_ruby(python_code: str) -> str:
    """
    Transpile Python code to Ruby.
    
    Args:
        python_code: Python source code string
        
    Returns:
        Ruby source code string
    """
    try:
        tree = ast.parse(python_code)
        transpiler = PythonToRubyTranspiler()
        transpiler.visit(tree)
        return transpiler.get_ruby_code()
    except SyntaxError as e:
        return f"# Syntax error in Python code: {e}"
    except Exception as e:
        return f"# Transpilation error: {e}"


def transpile_file(input_file: str, output_file: Optional[str] = None) -> None:
    """
    Transpile a Python file to Ruby.
    
    Args:
        input_file: Path to input Python file
        output_file: Path to output Ruby file (default: same name with .rb extension)
    """
    input_path = Path(input_file)
    
    if not input_path.exists():
        print(f"Error: File not found: {input_file}", file=sys.stderr)
        sys.exit(1)
    
    # Read Python code
    with open(input_path, 'r', encoding='utf-8') as f:
        python_code = f.read()
    
    # Transpile
    print(f"Transpiling {input_file}...")
    ruby_code = transpile_python_to_ruby(python_code)
    
    # Determine output file
    if output_file is None:
        output_file = str(input_path.with_suffix('.rb'))
    
    # Write Ruby code
    with open(output_file, 'w', encoding='utf-8') as f:
        f.write(ruby_code)
    
    print(f"✅ Generated Ruby file: {output_file}")
    print()
    print("⚠️  IMPORTANT: Manual review required!")
    print("   - Check complex expressions and logic")
    print("   - Verify library/method mappings")
    print("   - Test the Ruby code thoroughly")
    print("   - Add missing require statements")
    print("   - Handle Python-specific features manually")


def main():
    """Main entry point."""
    parser = argparse.ArgumentParser(
        description='Python to Ruby Transpiler - Convert Python code to Ruby',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  # Transpile a Python file
  python3 tools/py2ruby_transpiler.py script.py
  
  # Specify output file
  python3 tools/py2ruby_transpiler.py script.py -o output.rb
  
  # Transpile from stdin
  echo "print('hello')" | python3 tools/py2ruby_transpiler.py -

Note: This is a best-effort transpiler. Manual review and testing
are ALWAYS required. Complex Python features may need manual conversion.
        """
    )
    
    parser.add_argument(
        'input',
        help='Python file to transpile (use "-" for stdin)'
    )
    
    parser.add_argument(
        '-o', '--output',
        help='Output Ruby file (default: same name with .rb extension)'
    )
    
    parser.add_argument(
        '--show-ast',
        action='store_true',
        help='Show Python AST for debugging'
    )
    
    args = parser.parse_args()
    
    # Handle stdin
    if args.input == '-':
        python_code = sys.stdin.read()
        
        if args.show_ast:
            tree = ast.parse(python_code)
            print("=== Python AST ===")
            print(ast.dump(tree, indent=2))
            print()
        
        ruby_code = transpile_python_to_ruby(python_code)
        
        if args.output:
            with open(args.output, 'w') as f:
                f.write(ruby_code)
            print(f"✅ Generated: {args.output}")
        else:
            print(ruby_code)
    else:
        # Handle file
        transpile_file(args.input, args.output)


if __name__ == '__main__':
    main()
