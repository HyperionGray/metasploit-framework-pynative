#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
Modular Python to Ruby Transpiler CLI

Command-line interface for the refactored Python to Ruby transpiler.
This replaces the monolithic py2ruby_transpiler.py with a cleaner,
modular implementation.
"""

import sys
import ast
import argparse
from pathlib import Path
from .transpiler import transpile_python_to_ruby


def transpile_file(input_file: str, output_file: str = None):
    """
    Transpile a Python file to Ruby.
    
    Args:
        input_file: Path to input Python file
        output_file: Path to output Ruby file (optional)
    """
    input_path = Path(input_file)
    
    if not input_path.exists():
        print(f"❌ Error: Input file '{input_file}' not found")
        return False
    
    # Determine output file
    if output_file:
        output_path = Path(output_file)
    else:
        output_path = input_path.with_suffix('.rb')
    
    print(f"🔄 Transpiling: {input_path} -> {output_path}")
    
    try:
        # Read Python code
        with open(input_path, 'r', encoding='utf-8') as f:
            python_code = f.read()
        
        # Transpile to Ruby
        ruby_code = transpile_python_to_ruby(python_code)
        
        # Write Ruby code
        with open(output_path, 'w', encoding='utf-8') as f:
            f.write(ruby_code)
        
        print(f"✅ Generated Ruby file: {output_path}")
        print()
        print("⚠️  IMPORTANT: Manual review required!")
        print("   - Check complex expressions and logic")
        print("   - Verify library/method mappings")
        print("   - Test the Ruby code thoroughly")
        print("   - Add missing require statements")
        print("   - Handle Python-specific features manually")
        
        return True
        
    except Exception as e:
        print(f"❌ Error transpiling file: {e}")
        return False


def main():
    """Main entry point."""
    parser = argparse.ArgumentParser(
        description='Modular Python to Ruby Transpiler - Convert Python code to Ruby',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  # Transpile a Python file
  python3 -m tools.py2ruby script.py
  
  # Specify output file
  python3 -m tools.py2ruby script.py -o output.rb
  
  # Transpile from stdin
  echo "print('hello')" | python3 -m tools.py2ruby -

Note: This is a best-effort transpiler. Manual review and testing
are ALWAYS required. Complex Python features may need manual conversion.

This modular version provides better maintainability and extensibility
compared to the original monolithic transpiler.
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
    
    parser.add_argument(
        '--version',
        action='version',
        version='Modular Python to Ruby Transpiler 1.0.0'
    )
    
    args = parser.parse_args()
    
    # Handle stdin
    if args.input == '-':
        python_code = sys.stdin.read()
        
        if args.show_ast:
            try:
                tree = ast.parse(python_code)
                print("=== Python AST ===")
                print(ast.dump(tree, indent=2))
                print()
            except SyntaxError as e:
                print(f"❌ Syntax error in Python code: {e}")
                return 1
        
        ruby_code = transpile_python_to_ruby(python_code)
        
        if args.output:
            with open(args.output, 'w') as f:
                f.write(ruby_code)
            print(f"✅ Generated: {args.output}")
        else:
            print(ruby_code)
    else:
        # Handle file
        success = transpile_file(args.input, args.output)
        return 0 if success else 1


if __name__ == '__main__':
    sys.exit(main())