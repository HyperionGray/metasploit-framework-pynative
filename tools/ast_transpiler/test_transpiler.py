#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
Test Suite for AST-Based Ruby to Python Transpiler

This test suite validates that the AST transpiler correctly translates
Ruby code to Python code through proper AST-to-AST translation.
"""

import unittest
import sys
from pathlib import Path

# Add the transpiler directory to the path
sys.path.insert(0, str(Path(__file__).parent.parent))

from ast_transpiler.ast_translator import ASTTranspiler


class TestBasicSyntax(unittest.TestCase):
    """Test basic Ruby to Python syntax translation"""
    
    def setUp(self):
        self.transpiler = ASTTranspiler()
    
    def test_simple_class(self):
        """Test simple class definition"""
        ruby = "class Foo; end"
        python = self.transpiler.transpile_code(ruby)
        self.assertIn("class Foo", python)
        self.assertIn("pass", python)
    
    def test_class_with_superclass(self):
        """Test class with inheritance"""
        ruby = "class Foo < Bar; end"
        python = self.transpiler.transpile_code(ruby)
        self.assertIn("class Foo(Bar)", python)
    
    def test_method_definition(self):
        """Test method definition"""
        ruby = "class Foo; def hello; end; end"
        python = self.transpiler.transpile_code(ruby)
        self.assertIn("def hello(self)", python)
    
    def test_method_with_parameters(self):
        """Test method with parameters"""
        ruby = "class Foo; def greet(name); end; end"
        python = self.transpiler.transpile_code(ruby)
        self.assertIn("def greet(self, name)", python)
    
    def test_method_call(self):
        """Test method call"""
        ruby = "class Foo; def hello; puts 'world'; end; end"
        python = self.transpiler.transpile_code(ruby)
        self.assertIn("print('world')", python)


class TestVariables(unittest.TestCase):
    """Test variable translation"""
    
    def setUp(self):
        self.transpiler = ASTTranspiler()
    
    def test_instance_variable(self):
        """Test instance variable (@name → self.name)"""
        ruby = "class Foo; def init; @name = 'test'; end; end"
        python = self.transpiler.transpile_code(ruby)
        self.assertIn("self.name = 'test'", python)
    
    def test_instance_variable_read(self):
        """Test reading instance variable"""
        ruby = "class Foo; def get_name; return @name; end; end"
        python = self.transpiler.transpile_code(ruby)
        self.assertIn("self.name", python)
    
    def test_class_variable(self):
        """Test class variable (@@count → cls.count)"""
        ruby = "class Foo; def init; @@count = 0; end; end"
        python = self.transpiler.transpile_code(ruby)
        self.assertIn("cls.count = 0", python)
    
    def test_global_variable(self):
        """Test global variable ($debug → DEBUG)"""
        ruby = "class Foo; def init; $debug = true; end; end"
        python = self.transpiler.transpile_code(ruby)
        self.assertIn("DEBUG = True", python)


class TestControlFlow(unittest.TestCase):
    """Test control flow translation"""
    
    def setUp(self):
        self.transpiler = ASTTranspiler()
    
    def test_if_statement(self):
        """Test if statement"""
        ruby = "if x; a; end"
        python = self.transpiler.transpile_code(ruby)
        self.assertIn("if ", python)
    
    def test_if_else_statement(self):
        """Test if-else statement"""
        ruby = "if x; a; else; b; end"
        python = self.transpiler.transpile_code(ruby)
        self.assertIn("if ", python)
        self.assertIn("else:", python)
    
    def test_unless_statement(self):
        """Test unless statement (unless x → if not x)"""
        ruby = "unless x; a; end"
        python = self.transpiler.transpile_code(ruby)
        self.assertIn("if not ", python)
    
    def test_return_statement(self):
        """Test return statement"""
        ruby = "def foo; return 42; end"
        python = self.transpiler.transpile_code(ruby)
        self.assertIn("return 42", python)


class TestDataTypes(unittest.TestCase):
    """Test data type translation"""
    
    def setUp(self):
        self.transpiler = ASTTranspiler()
    
    def test_integer(self):
        """Test integer literal"""
        ruby = "x = 42"
        python = self.transpiler.transpile_code(ruby)
        self.assertIn("42", python)
    
    def test_string(self):
        """Test string literal"""
        ruby = "x = 'hello'"
        python = self.transpiler.transpile_code(ruby)
        self.assertIn("'hello'", python)
    
    def test_symbol(self):
        """Test symbol (:name → 'name')"""
        ruby = "x = :symbol"
        python = self.transpiler.transpile_code(ruby)
        self.assertIn("'symbol'", python)
    
    def test_array(self):
        """Test array ([1, 2, 3] → [1, 2, 3])"""
        ruby = "x = [1, 2, 3]"
        python = self.transpiler.transpile_code(ruby)
        self.assertIn("[1, 2, 3]", python)
    
    def test_hash(self):
        """Test hash ({a: 1} → {'a': 1})"""
        ruby = "x = {:a => 1}"
        python = self.transpiler.transpile_code(ruby)
        self.assertIn("{'a': 1}", python)


class TestRubySpecificFeatures(unittest.TestCase):
    """Test Ruby-specific feature translation"""
    
    def setUp(self):
        self.transpiler = ASTTranspiler()
    
    def test_super_call(self):
        """Test super call (super(args) → super().__init__(args))"""
        ruby = "class Foo < Bar; def initialize(x); super(x); end; end"
        python = self.transpiler.transpile_code(ruby)
        self.assertIn("super().__init__", python)
    
    def test_method_with_question_mark(self):
        """Test method name with ? (valid? → is_valid)"""
        ruby = "class Foo; def check; return valid?; end; end"
        python = self.transpiler.transpile_code(ruby)
        self.assertIn("is_valid", python)
    
    def test_boolean_values(self):
        """Test boolean translation (true/false → True/False)"""
        ruby = "x = true; y = false"
        python = self.transpiler.transpile_code(ruby)
        # Note: Booleans are keywords in Ruby AST
        self.assertIn("True", python.upper())


class TestMetasploitModule(unittest.TestCase):
    """Test Metasploit module translation"""
    
    def setUp(self):
        self.transpiler = ASTTranspiler()
    
    def test_basic_msf_module(self):
        """Test basic Metasploit module structure"""
        ruby = """
class MetasploitModule < Msf::Exploit::Remote
  def initialize(info = {})
    super(info)
    @name = 'Test Exploit'
  end
end
"""
        python = self.transpiler.transpile_code(ruby)
        self.assertIn("class MetasploitModule", python)
        self.assertIn("Msf.Exploit.Remote", python)
        self.assertIn("def initialize(self)", python)
        self.assertIn("super().__init__()", python)
        self.assertIn("self.name = 'Test Exploit'", python)
    
    def test_check_method(self):
        """Test check method with conditional return"""
        ruby = """
class MetasploitModule < Msf::Exploit::Remote
  def check
    if target_vulnerable?
      return :vulnerable
    else
      return :safe
    end
  end
end
"""
        python = self.transpiler.transpile_code(ruby)
        self.assertIn("def check(self)", python)
        self.assertIn("is_target_vulnerable", python)
        self.assertIn("return 'vulnerable'", python)
        self.assertIn("return 'safe'", python)


class TestComplexExamples(unittest.TestCase):
    """Test complex real-world examples"""
    
    def setUp(self):
        self.transpiler = ASTTranspiler()
    
    def test_nested_classes(self):
        """Test nested class definitions"""
        ruby = """
class Outer
  class Inner < Base
    def method
      @var = 123
    end
  end
end
"""
        python = self.transpiler.transpile_code(ruby)
        self.assertIn("class Outer", python)
        self.assertIn("class Inner(Base)", python)
        self.assertIn("self.var = 123", python)


def run_tests():
    """Run all tests and print results"""
    # Create test suite
    loader = unittest.TestLoader()
    suite = unittest.TestSuite()
    
    # Add all test classes
    suite.addTests(loader.loadTestsFromTestCase(TestBasicSyntax))
    suite.addTests(loader.loadTestsFromTestCase(TestVariables))
    suite.addTests(loader.loadTestsFromTestCase(TestControlFlow))
    suite.addTests(loader.loadTestsFromTestCase(TestDataTypes))
    suite.addTests(loader.loadTestsFromTestCase(TestRubySpecificFeatures))
    suite.addTests(loader.loadTestsFromTestCase(TestMetasploitModule))
    suite.addTests(loader.loadTestsFromTestCase(TestComplexExamples))
    
    # Run tests
    runner = unittest.TextTestRunner(verbosity=2)
    result = runner.run(suite)
    
    # Print summary
    print("\n" + "=" * 70)
    print("Test Summary")
    print("=" * 70)
    print(f"Tests run: {result.testsRun}")
    print(f"Successes: {result.testsRun - len(result.failures) - len(result.errors)}")
    print(f"Failures: {len(result.failures)}")
    print(f"Errors: {len(result.errors)}")
    
    if result.wasSuccessful():
        print("\n✅ All tests passed!")
        return 0
    else:
        print("\n❌ Some tests failed!")
        return 1


if __name__ == '__main__':
    sys.exit(run_tests())
