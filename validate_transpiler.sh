#!/bin/bash
# Test script to validate transpiler functionality

echo "Testing Ruby-to-Python Transpiler..."
echo "======================================"

# Test Python syntax
echo "Checking Python syntax..."
python3 -m py_compile ruby_ast_parser.py
if [ $? -eq 0 ]; then
    echo "✅ ruby_ast_parser.py syntax OK"
else
    echo "❌ ruby_ast_parser.py syntax error"
    exit 1
fi

python3 -m py_compile python_ast_generator.py
if [ $? -eq 0 ]; then
    echo "✅ python_ast_generator.py syntax OK"
else
    echo "❌ python_ast_generator.py syntax error"
    exit 1
fi

# Test imports
echo "Testing imports..."
python3 test_transpiler.py
if [ $? -eq 0 ]; then
    echo "✅ All tests passed"
else
    echo "❌ Tests failed"
    exit 1
fi

echo "======================================"
echo "✅ Transpiler validation complete!"