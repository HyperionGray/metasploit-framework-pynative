#!/usr/bin/env python3
"""
Test script to validate the Ruby-to-Python transpiler functionality
"""

def test_imports():
    """Test that both transpiler modules can be imported"""
    try:
        from ruby_ast_parser import RubyASTParser, RubyASTNode
        from python_ast_generator import PythonASTGenerator, PythonASTContext
        print("✅ All imports successful")
        return True
    except ImportError as e:
        print(f"❌ Import failed: {e}")
        return False

def test_basic_functionality():
    """Test basic functionality without Ruby runtime"""
    try:
        from python_ast_generator import PythonASTGenerator, PythonASTContext
        from ruby_ast_parser import RubyASTNode
        
        # Create a simple Ruby AST node for testing
        test_node = RubyASTNode('program', children=[
            RubyASTNode('int', value=42),
            RubyASTNode('string_literal', children=[
                RubyASTNode('tstring_content', value='hello')
            ])
        ])
        
        # Test Python AST generation
        generator = PythonASTGenerator()
        python_ast = generator.generate_python_ast(test_node)
        
        if python_ast:
            print("✅ Python AST generation successful")
            return True
        else:
            print("❌ Python AST generation failed")
            return False
            
    except Exception as e:
        print(f"❌ Basic functionality test failed: {e}")
        return False

def main():
    """Run all tests"""
    print("Testing Ruby-to-Python Transpiler...")
    print("=" * 40)
    
    success = True
    
    # Test imports
    if not test_imports():
        success = False
    
    # Test basic functionality
    if not test_basic_functionality():
        success = False
    
    print("=" * 40)
    if success:
        print("✅ All tests passed!")
        return 0
    else:
        print("❌ Some tests failed!")
        return 1

if __name__ == '__main__':
    exit(main())