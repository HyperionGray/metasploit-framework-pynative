#!/usr/bin/env python3
"""
Ruby AST Parser for Ruby-to-Python Transpiler

This module provides Ruby AST parsing capabilities using Ruby's Ripper
to generate structured AST representations that can be systematically
converted to Python AST nodes.
"""

import json
import subprocess
import tempfile
import os
from typing import Dict, List, Any, Optional, Union
from dataclasses import dataclass
from pathlib import Path


@dataclass
class RubyASTNode:
    """Represents a Ruby AST node with type and children"""
    node_type: str
    value: Any = None
    children: List['RubyASTNode'] = None
    location: Dict[str, int] = None
    
    def __post_init__(self):
        if self.children is None:
            self.children = []


class RubyASTParser:
    """Parser for Ruby code using Ruby's Ripper to generate AST"""
    
    def __init__(self):
        self.ruby_parser_script = self._create_ruby_parser_script()
    
    def _create_ruby_parser_script(self) -> str:
        """Create Ruby script that uses Ripper to parse Ruby code and output JSON AST"""
        return '''
require 'ripper'
require 'json'

class ASTBuilder < Ripper::SexpBuilder
  def initialize(source, filename = nil, lineno = 1)
    super
    @source_lines = source.lines
  end
  
  # Override to add location information
  def on_program(stmts)
    [:program, stmts]
  end
  
  def on_class(name, superclass, body)
    [:class, name, superclass, body, location_info]
  end
  
  def on_module(name, body)
    [:module, name, body, location_info]
  end
  
  def on_def(name, params, body)
    [:def, name, params, body, location_info]
  end
  
  def on_call(receiver, method, args)
    [:call, receiver, method, args, location_info]
  end
  
  def on_method_add_arg(call, args)
    [:method_add_arg, call, args, location_info]
  end
  
  def on_assign(lhs, rhs)
    [:assign, lhs, rhs, location_info]
  end
  
  def on_var_field(name)
    [:var_field, name, location_info]
  end
  
  def on_var_ref(name)
    [:var_ref, name, location_info]
  end
  
  def on_const(name)
    [:const, name, location_info]
  end
  
  def on_const_ref(name)
    [:const_ref, name, location_info]
  end
  
  def on_hash(assocs)
    [:hash, assocs, location_info]
  end
  
  def on_assoc_new(key, value)
    [:assoc_new, key, value, location_info]
  end
  
  def on_array(elements)
    [:array, elements, location_info]
  end
  
  def on_string_literal(string)
    [:string_literal, string, location_info]
  end
  
  def on_string_content()
    [:string_content, location_info]
  end
  
  def on_tstring_content(content)
    [:tstring_content, content, location_info]
  end
  
  def on_symbol_literal(symbol)
    [:symbol_literal, symbol, location_info]
  end
  
  def on_symbol(name)
    [:symbol, name, location_info]
  end
  
  def on_if(condition, then_body, else_body)
    [:if, condition, then_body, else_body, location_info]
  end
  
  def on_unless(condition, then_body, else_body)
    [:unless, condition, then_body, else_body, location_info]
  end
  
  def on_while(condition, body)
    [:while, condition, body, location_info]
  end
  
  def on_for(var, iterable, body)
    [:for, var, iterable, body, location_info]
  end
  
  def on_block_var(params, locals)
    [:block_var, params, locals, location_info]
  end
  
  def on_brace_block(params, body)
    [:brace_block, params, body, location_info]
  end
  
  def on_do_block(params, body)
    [:do_block, params, body, location_info]
  end
  
  def on_return(value)
    [:return, value, location_info]
  end
  
  def on_yield(args)
    [:yield, args, location_info]
  end
  
  def on_binary(left, op, right)
    [:binary, left, op, right, location_info]
  end
  
  def on_unary(op, operand)
    [:unary, op, operand, location_info]
  end
  
  def on_paren(content)
    [:paren, content, location_info]
  end
  
  def on_int(value)
    [:int, value, location_info]
  end
  
  def on_float(value)
    [:float, value, location_info]
  end
  
  def on_rational(value)
    [:rational, value, location_info]
  end
  
  def on_imaginary(value)
    [:imaginary, value, location_info]
  end
  
  def on_kw(keyword)
    [:kw, keyword, location_info]
  end
  
  def on_regexp_literal(pattern, flags)
    [:regexp_literal, pattern, flags, location_info]
  end
  
  private
  
  def location_info
    {
      line: lineno,
      column: column
    }
  end
end

# Read source code from STDIN or file
if ARGV.length > 0
  source = File.read(ARGV[0])
else
  source = STDIN.read
end

begin
  parser = ASTBuilder.new(source)
  ast = parser.parse
  
  if ast
    puts JSON.generate(ast)
  else
    STDERR.puts "Parse error: Unable to parse Ruby code"
    exit 1
  end
rescue => e
  STDERR.puts "Error: #{e.message}"
  exit 1
end
'''
    
    def parse_ruby_code(self, ruby_code: str, filename: Optional[str] = None) -> RubyASTNode:
        """Parse Ruby code and return AST representation"""
        try:
            # Create temporary file with Ruby code
            with tempfile.NamedTemporaryFile(mode='w', suffix='.rb', delete=False) as temp_file:
                temp_file.write(ruby_code)
                temp_file.flush()
                
                # Create temporary Ruby parser script
                with tempfile.NamedTemporaryFile(mode='w', suffix='.rb', delete=False) as parser_file:
                    parser_file.write(self.ruby_parser_script)
                    parser_file.flush()
                    
                    try:
                        # Run Ruby parser
                        result = subprocess.run(
                            ['ruby', parser_file.name, temp_file.name],
                            capture_output=True,
                            text=True,
                            timeout=30
                        )
                        
                        if result.returncode != 0:
                            raise RuntimeError(f"Ruby parser failed: {result.stderr}")
                        
                        # Parse JSON output
                        ast_data = json.loads(result.stdout)
                        return self._build_ast_node(ast_data)
                        
                    finally:
                        # Clean up temporary files
                        os.unlink(parser_file.name)
                
        except subprocess.TimeoutExpired:
            raise RuntimeError("Ruby parser timed out")
        except json.JSONDecodeError as e:
            raise RuntimeError(f"Failed to parse AST JSON: {e}")
        except Exception as e:
            raise RuntimeError(f"Ruby parsing failed: {e}")
        finally:
            if 'temp_file' in locals():
                try:
                    os.unlink(temp_file.name)
                except:
                    pass
    
    def parse_ruby_file(self, file_path: Union[str, Path]) -> RubyASTNode:
        """Parse Ruby file and return AST representation"""
        file_path = Path(file_path)
        
        if not file_path.exists():
            raise FileNotFoundError(f"Ruby file not found: {file_path}")
        
        with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
            ruby_code = f.read()
        
        return self.parse_ruby_code(ruby_code, str(file_path))
    
    def _build_ast_node(self, data: Any) -> RubyASTNode:
        """Recursively build AST node from parsed data"""
        if not isinstance(data, list) or len(data) == 0:
            return RubyASTNode('literal', value=data)
        
        node_type = data[0]
        
        # Handle different node structures
        if len(data) == 1:
            return RubyASTNode(node_type)
        
        # Extract location info if present (usually last element)
        location = None
        children_data = data[1:]
        
        if (len(children_data) > 0 and 
            isinstance(children_data[-1], dict) and 
            'line' in children_data[-1]):
            location = children_data[-1]
            children_data = children_data[:-1]
        
        # Build children nodes
        children = []
        value = None
        
        if len(children_data) == 1 and not isinstance(children_data[0], list):
            # Single value node
            value = children_data[0]
        else:
            # Multiple children or complex structure
            for child_data in children_data:
                if isinstance(child_data, list):
                    children.append(self._build_ast_node(child_data))
                elif child_data is not None:
                    children.append(RubyASTNode('literal', value=child_data))
        
        return RubyASTNode(
            node_type=node_type,
            value=value,
            children=children,
            location=location
        )
    
    def print_ast(self, node: RubyASTNode, indent: int = 0) -> None:
        """Print AST structure for debugging"""
        prefix = "  " * indent
        location_str = ""
        if node.location:
            location_str = f" @{node.location.get('line', '?')}:{node.location.get('column', '?')}"
        
        if node.value is not None:
            print(f"{prefix}{node.node_type}: {repr(node.value)}{location_str}")
        else:
            print(f"{prefix}{node.node_type}{location_str}")
        
        for child in node.children:
            self.print_ast(child, indent + 1)


def main():
    """Test the Ruby AST parser"""
    import argparse
    
    parser = argparse.ArgumentParser(description="Parse Ruby code and display AST")
    parser.add_argument('file', nargs='?', help='Ruby file to parse')
    parser.add_argument('--code', help='Ruby code string to parse')
    
    args = parser.parse_args()
    
    ruby_parser = RubyASTParser()
    
    try:
        if args.file:
            ast = ruby_parser.parse_ruby_file(args.file)
        elif args.code:
            ast = ruby_parser.parse_ruby_code(args.code)
        else:
            # Read from stdin
            import sys
            code = sys.stdin.read()
            ast = ruby_parser.parse_ruby_code(code)
        
        print("Ruby AST:")
        print("=" * 40)
        ruby_parser.print_ast(ast)
        
    except Exception as e:
        print(f"Error: {e}")
        return 1
    
    return 0


if __name__ == '__main__':
    exit(main())