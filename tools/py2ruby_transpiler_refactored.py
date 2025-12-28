#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
Refactored Python to Ruby Transpiler

A modular transpiler that converts Python code to Ruby, now split into
focused components for better maintainability and reduced file size.

Author: Metasploit Framework Python Migration Team
License: BSD-3-Clause
"""

import ast
import sys
import argparse
from pathlib import Path
from typing import Dict, List, Optional, Set, Any

from .transpiler_config import TranspilerMappings, TranspilerConfig
from .ast_handlers import (
    ExpressionHandler, StatementHandler, 
    FunctionHandler, ClassHandler
)


class PythonToRubyTranspiler(ast.NodeVisitor):
    """
    Modular AST-based Python to Ruby transpiler.
    
    Now uses specialized handlers for different types of AST nodes
    to improve maintainability and reduce complexity.
    """
    
    def __init__(self):
        self.output = []
        self.indent_level = 0
        self.indent_string = TranspilerConfig.DEFAULT_INDENT
        self.imports = []
        self.in_class = False
        self.in_function = False
        self.class_name = None
        
        # Initialize mappings and handlers
        self.mappings = TranspilerMappings()
        self.config = TranspilerConfig()
        
        # Initialize specialized handlers
        self.expression_handler = ExpressionHandler(self)
        self.statement_handler = StatementHandler(self)
        self.function_handler = FunctionHandler(self)
        self.class_handler = ClassHandler(self)
    
    def get_indent(self) -> str:
        """Get current indentation string."""
        return self.indent_string * self.indent_level
    
    def add_line(self, line: str) -> None:
        """Add a line to output with proper indentation."""
        if line.strip():
            self.output.append(self.get_indent() + line)
        else:
            self.output.append("")
    
    def visit_Module(self, node: ast.Module) -> str:
        """Visit module node (root of AST)."""
        for stmt in node.body:
            result = self.visit(stmt)
            if result:
                self.output.append(result)
        
        return '\n'.join(self.output)
    
    # Expression nodes - delegate to ExpressionHandler
    def visit_Name(self, node: ast.Name) -> str:
        return self.expression_handler.handle_name(node)
    
    def visit_Constant(self, node: ast.Constant) -> str:
        return self.expression_handler.handle_constant(node)
    
    def visit_BinOp(self, node: ast.BinOp) -> str:
        return self.expression_handler.handle_binop(node)
    
    def visit_Compare(self, node: ast.Compare) -> str:
        return self.expression_handler.handle_compare(node)
    
    # Statement nodes - delegate to StatementHandler
    def visit_Assign(self, node: ast.Assign) -> str:
        return self.statement_handler.handle_assign(node)
    
    def visit_If(self, node: ast.If) -> str:
        return self.statement_handler.handle_if(node)
    
    def visit_For(self, node: ast.For) -> str:
        return self.statement_handler.handle_for(node)
    
    def visit_While(self, node: ast.While) -> str:
        return self.statement_handler.handle_while(node)
    
    # Function nodes - delegate to FunctionHandler
    def visit_FunctionDef(self, node: ast.FunctionDef) -> str:
        return self.function_handler.handle_function_def(node)
    
    def visit_Call(self, node: ast.Call) -> str:
        return self.function_handler.handle_call(node)
    
    # Class nodes - delegate to ClassHandler
    def visit_ClassDef(self, node: ast.ClassDef) -> str:
        return self.class_handler.handle_class_def(node)
    
    # Simple expression nodes
    def visit_Expr(self, node: ast.Expr) -> str:
        """Visit expression statement."""
        return self.visit(node.value)
    
    def visit_Attribute(self, node: ast.Attribute) -> str:
        """Visit attribute access (obj.attr)."""
        value = self.visit(node.value)
        attr = node.attr
        
        # Handle method name mappings
        if attr in self.mappings.METHOD_MAPPINGS:
            attr = self.mappings.METHOD_MAPPINGS[attr]
        
        return f"{value}.{attr}"
    
    def visit_Subscript(self, node: ast.Subscript) -> str:
        """Visit subscript access (obj[key])."""
        value = self.visit(node.value)
        slice_val = self.visit(node.slice)
        return f"{value}[{slice_val}]"
    
    def visit_List(self, node: ast.List) -> str:
        """Visit list literal."""
        elements = [self.visit(elt) for elt in node.elts]
        return f"[{', '.join(elements)}]"
    
    def visit_Dict(self, node: ast.Dict) -> str:
        """Visit dictionary literal."""
        pairs = []
        for key, value in zip(node.keys, node.values):
            key_str = self.visit(key)
            value_str = self.visit(value)
            pairs.append(f"{key_str} => {value_str}")
        return f"{{{', '.join(pairs)}}}"
    
    def visit_Tuple(self, node: ast.Tuple) -> str:
        """Visit tuple literal."""
        elements = [self.visit(elt) for elt in node.elts]
        return f"[{', '.join(elements)}]"  # Ruby uses arrays for tuples
    
    def visit_Return(self, node: ast.Return) -> str:
        """Visit return statement."""
        if node.value:
            value = self.visit(node.value)
            return f"return {value}"
        else:
            return "return"
    
    def visit_Pass(self, node: ast.Pass) -> str:
        """Visit pass statement."""
        return "# pass"
    
    def visit_Break(self, node: ast.Break) -> str:
        """Visit break statement."""
        return "break"
    
    def visit_Continue(self, node: ast.Continue) -> str:
        """Visit continue statement."""
        return "next"
    
    def generic_visit(self, node: ast.AST) -> str:
        """Handle unsupported nodes."""
        node_type = type(node).__name__
        if self.config.STRICT_MODE:
            raise NotImplementedError(f"Unsupported AST node: {node_type}")
        else:
            return f"# TODO: Unsupported {node_type}"


def transpile_python_to_ruby(python_code: str) -> str:
    """
    Transpile Python source code to Ruby.
    
    Args:
        python_code: Python source code as string
        
    Returns:
        Ruby source code as string
    """
    try:
        # Parse Python code to AST
        tree = ast.parse(python_code)
        
        # Create transpiler and convert
        transpiler = PythonToRubyTranspiler()
        ruby_code = transpiler.visit(tree)
        
        # Add header comment
        header = [
            "#!/usr/bin/env ruby",
            "# -*- coding: utf-8 -*-",
            "#",
            "# This file was automatically transpiled from Python to Ruby",
            "# Manual review and testing is required!",
            "#",
            "",
        ]
        
        return '\n'.join(header) + ruby_code
        
    except SyntaxError as e:
        raise ValueError(f"Invalid Python syntax: {e}")
    except Exception as e:
        raise RuntimeError(f"Transpilation failed: {e}")


def transpile_file(input_file: str, output_file: str = None) -> None:
    """
    Transpile a Python file to Ruby.
    
    Args:
        input_file: Path to input Python file
        output_file: Path to output Ruby file (optional)
    """
    input_path = Path(input_file)
    
    if not input_path.exists():
        raise FileNotFoundError(f"Input file not found: {input_file}")
    
    # Determine output file
    if output_file is None:
        output_file = TranspilerConfig.get_output_filename(input_file)
    
    output_path = Path(output_file)
    
    print(f"🔄 Transpiling: {input_file} → {output_file}")
    
    # Read Python code
    try:
        with open(input_path, 'r', encoding='utf-8') as f:
            python_code = f.read()
    except UnicodeDecodeError:
        with open(input_path, 'r', encoding='latin-1') as f:
            python_code = f.read()
    
    # Transpile to Ruby
    ruby_code = transpile_python_to_ruby(python_code)
    
    # Write Ruby code
    with open(output_path, 'w', encoding='utf-8') as f:
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
  python3 tools/py2ruby_transpiler_refactored.py script.py
  
  # Specify output file
  python3 tools/py2ruby_transpiler_refactored.py script.py -o output.rb
  
  # Transpile from stdin
  echo "print('hello')" | python3 tools/py2ruby_transpiler_refactored.py -

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