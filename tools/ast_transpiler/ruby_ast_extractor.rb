#!/usr/bin/env ruby
# -*- coding: utf-8 -*-

##
# Ruby AST Extractor
#
# This script uses Ruby's built-in Ripper library to parse Ruby source code
# and extract a structured Abstract Syntax Tree (AST) representation.
# The AST is then serialized to JSON for consumption by Python.
##

require 'ripper'
require 'json'
require 'pp'

module RubyASTExtractor
  ##
  # Parse Ruby source and extract structured AST
  ##
  class Parser
    def initialize(source, filename = '(ruby)')
      @source = source
      @filename = filename
      @sexp = nil
    end

    def parse
      @sexp = Ripper.sexp(@source, @filename)
      unless @sexp
        # Try to get more detailed error information
        begin
          # Use Ripper.lex to get tokenization errors
          tokens = Ripper.lex(@source)
          raise "Failed to parse Ruby source: Tokenization succeeded but parsing failed. Check syntax."
        rescue => lex_error
          raise "Failed to parse Ruby source: #{lex_error.message}"
        end
      end
      process_node(@sexp)
    end

    private

    def process_node(node)
      return nil if node.nil?
      
      # Handle arrays (most nodes are arrays in Ripper)
      if node.is_a?(Array)
        # Check if this is an S-expression (starts with a symbol)
        if node[0].is_a?(Symbol)
          node_type = node[0]
        else
          # This is an array of statements or nodes
          return node.map { |n| process_node(n) }
        end
        
        case node_type
        when :program
          {
            type: 'Program',
            body: process_node(node[1])
          }
        when :stmts_add
          {
            type: 'StatementsAdd',
            statements: process_node(node[1]),
            statement: process_node(node[2])
          }
        when :void_stmt
          {
            type: 'VoidStatement'
          }
        when :class
          {
            type: 'ClassDefinition',
            name: process_node(node[1]),
            superclass: process_node(node[2]),
            body: process_node(node[3])
          }
        when :const_ref
          {
            type: 'ConstantReference',
            name: process_node(node[1])
          }
        when :const_path_ref
          {
            type: 'ConstantPathReference',
            parent: process_node(node[1]),
            name: process_node(node[2])
          }
        when :@const
          {
            type: 'Constant',
            value: node[1],
            position: {line: node[2][0], column: node[2][1]}
          }
        when :module
          {
            type: 'ModuleDefinition',
            name: process_node(node[1]),
            body: process_node(node[2])
          }
        when :def
          {
            type: 'MethodDefinition',
            name: process_node(node[1]),
            params: process_node(node[2]),
            body: process_node(node[3])
          }
        when :@ivar
          {
            type: 'InstanceVariable',
            name: node[1],
            position: {line: node[2][0], column: node[2][1]}
          }
        when :@cvar
          {
            type: 'ClassVariable',
            name: node[1],
            position: {line: node[2][0], column: node[2][1]}
          }
        when :@gvar
          {
            type: 'GlobalVariable',
            name: node[1],
            position: {line: node[2][0], column: node[2][1]}
          }
        when :var_field
          {
            type: 'VariableField',
            variable: process_node(node[1])
          }
        when :super
          {
            type: 'SuperCall',
            args: process_node(node[1])
          }
        when :zsuper
          {
            type: 'SuperCallWithoutArgs'
          }
        when :@ident
          {
            type: 'Identifier',
            value: node[1],
            position: {line: node[2][0], column: node[2][1]}
          }
        when :params
          {
            type: 'Parameters',
            required: process_params(node[1]),
            optional: process_params(node[2]),
            rest: process_node(node[3]),
            trailing: process_params(node[4]),
            block: process_node(node[5])
          }
        when :paren
          {
            type: 'Parentheses',
            content: process_node(node[1])
          }
        when :bodystmt
          {
            type: 'BodyStatement',
            body: process_node(node[1]),
            rescue_clause: process_node(node[2]),
            else_clause: process_node(node[3]),
            ensure_clause: process_node(node[4])
          }
        when :var_ref
          # Check if this is a constant reference (for superclass, etc.)
          if node[1].is_a?(Array) && node[1][0] == :@const
            {
              type: 'ConstantReference',
              name: process_node(node[1])
            }
          else
            {
              type: 'VariableReference',
              name: process_node(node[1])
            }
          end
        when :@kw
          {
            type: 'Keyword',
            value: node[1],
            position: {line: node[2][0], column: node[2][1]}
          }
        when :symbol_literal
          {
            type: 'SymbolLiteral',
            value: process_node(node[1])
          }
        when :symbol
          {
            type: 'Symbol',
            value: process_node(node[1])
          }
        when :string_literal
          {
            type: 'StringLiteral',
            parts: process_node(node[1])
          }
        when :string_content
          {
            type: 'StringContent',
            parts: node[1..-1].map { |n| process_node(n) }
          }
        when :@tstring_content
          {
            type: 'StringContent',
            value: node[1],
            position: {line: node[2][0], column: node[2][1]}
          }
        when :string_embexpr
          {
            type: 'StringInterpolation',
            expression: process_node(node[1])
          }
        when :@int
          {
            type: 'Integer',
            value: node[1].to_i,
            position: {line: node[2][0], column: node[2][1]}
          }
        when :@float
          {
            type: 'Float',
            value: node[1].to_f,
            position: {line: node[2][0], column: node[2][1]}
          }
        when :hash
          {
            type: 'Hash',
            pairs: process_node(node[1])
          }
        when :assoclist_from_args
          {
            type: 'AssociationList',
            pairs: node[1].map { |pair| process_node(pair) }
          }
        when :assoc_new
          {
            type: 'Association',
            key: process_node(node[1]),
            value: process_node(node[2])
          }
        when :array
          {
            type: 'Array',
            elements: process_node(node[1])
          }
        when :args_add_block
          {
            type: 'Arguments',
            args: process_node(node[1]),
            block: process_node(node[2])
          }
        when :arg_paren
          {
            type: 'ArgumentParentheses',
            args: process_node(node[1])
          }
        when :method_add_arg
          {
            type: 'MethodCall',
            method: process_node(node[1]),
            args: process_node(node[2])
          }
        when :method_add_block
          {
            type: 'MethodWithBlock',
            method: process_node(node[1]),
            block: process_node(node[2])
          }
        when :call
          {
            type: 'Call',
            receiver: process_node(node[1]),
            operator: node[2],
            method: process_node(node[3])
          }
        when :fcall
          {
            type: 'FunctionCall',
            name: process_node(node[1])
          }
        when :vcall
          {
            type: 'VariableCall',
            name: process_node(node[1])
          }
        when :command
          {
            type: 'Command',
            name: process_node(node[1]),
            args: process_node(node[2])
          }
        when :do_block
          {
            type: 'DoBlock',
            params: process_node(node[1]),
            body: process_node(node[2])
          }
        when :brace_block
          {
            type: 'BraceBlock',
            params: process_node(node[1]),
            body: process_node(node[2])
          }
        when :block_var
          {
            type: 'BlockVariable',
            params: process_node(node[1])
          }
        when :assign
          {
            type: 'Assignment',
            target: process_node(node[1]),
            value: process_node(node[2])
          }
        when :binary
          {
            type: 'BinaryOperation',
            left: process_node(node[1]),
            operator: node[2],
            right: process_node(node[3])
          }
        when :unary
          {
            type: 'UnaryOperation',
            operator: node[1],
            operand: process_node(node[2])
          }
        when :if
          {
            type: 'IfStatement',
            condition: process_node(node[1]),
            then_clause: process_node(node[2]),
            else_clause: process_node(node[3])
          }
        when :elsif
          {
            type: 'ElsifClause',
            condition: process_node(node[1]),
            then_clause: process_node(node[2]),
            else_clause: process_node(node[3])
          }
        when :else
          {
            type: 'ElseClause',
            body: process_node(node[1])
          }
        when :unless
          {
            type: 'UnlessStatement',
            condition: process_node(node[1]),
            then_clause: process_node(node[2]),
            else_clause: process_node(node[3])
          }
        when :while
          {
            type: 'WhileLoop',
            condition: process_node(node[1]),
            body: process_node(node[2])
          }
        when :until
          {
            type: 'UntilLoop',
            condition: process_node(node[1]),
            body: process_node(node[2])
          }
        when :for
          {
            type: 'ForLoop',
            variable: process_node(node[1]),
            iterable: process_node(node[2]),
            body: process_node(node[3])
          }
        when :case
          {
            type: 'CaseStatement',
            expr: process_node(node[1]),
            when_clauses: process_node(node[2])
          }
        when :when
          {
            type: 'WhenClause',
            values: process_node(node[1]),
            body: process_node(node[2]),
            next_when: process_node(node[3])
          }
        when :return
          {
            type: 'ReturnStatement',
            value: process_node(node[1])
          }
        when :break
          {
            type: 'BreakStatement',
            value: process_node(node[1])
          }
        when :next
          {
            type: 'NextStatement',
            value: process_node(node[1])
          }
        else
          # Generic handler for unknown node types
          {
            type: "Unknown_#{node_type}",
            raw: node[1..-1].map { |n| process_node(n) }
          }
        end
      elsif node.is_a?(String)
        node
      elsif node.is_a?(Symbol)
        node.to_s
      else
        node
      end
    end

    def process_params(params)
      return nil if params.nil?
      params.map { |p| process_node(p) }
    end
  end

  ##
  # Parse Ruby source and extract AST
  ##
  def self.parse(source, filename = '(ruby)')
    parser = Parser.new(source, filename)
    parser.parse
  end

  ##
  # Parse Ruby file and extract AST
  ##
  def self.parse_file(filename)
    source = File.read(filename)
    parse(source, filename)
  end
end

# Main execution
if __FILE__ == $PROGRAM_NAME
  if ARGV.empty?
    puts "Usage: #{$PROGRAM_NAME} <ruby_file>"
    puts "       #{$PROGRAM_NAME} -e '<ruby_code>'"
    exit 1
  end

  begin
    if ARGV[0] == '-e'
      source = ARGV[1]
      ast = RubyASTExtractor.parse(source)
    else
      filename = ARGV[0]
      unless File.exist?(filename)
        $stderr.puts "Error: File not found: #{filename}"
        exit 1
      end
      ast = RubyASTExtractor.parse_file(filename)
    end

    # Output AST as JSON
    puts JSON.pretty_generate(ast)
  rescue => e
    $stderr.puts "Error parsing Ruby code: #{e.message}"
    $stderr.puts e.backtrace.join("\n")
    exit 1
  end
end
