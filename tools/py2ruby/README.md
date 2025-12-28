# Modular Python to Ruby Transpiler

This directory contains the refactored, modular version of the Python to Ruby transpiler. The original monolithic `py2ruby_transpiler.py` (977 lines) has been broken down into focused modules for better maintainability and extensibility.

## Module Structure

### Core Modules

- **`__init__.py`** - Package initialization and exports
- **`transpiler.py`** - Main transpiler class with AST visitor coordination
- **`config.py`** - Configuration mappings (Python → Ruby conversions)
- **`code_generator.py`** - Ruby code generation utilities
- **`visitors.py`** - Specialized AST visitors for different Python constructs
- **`__main__.py`** - Command-line interface

### Key Improvements

1. **Separation of Concerns**: Each module has a single, focused responsibility
2. **Configuration Externalization**: All mapping dictionaries moved to `config.py`
3. **Specialized Visitors**: Different AST node types handled by focused visitor classes
4. **Code Generation Utilities**: Reusable Ruby code formatting functions
5. **Maintainable CLI**: Clean command-line interface separate from core logic

## Usage

### As a Module
```python
from tools.py2ruby import transpile_python_to_ruby

python_code = """
def hello(name):
    print(f"Hello, {name}!")
"""

ruby_code = transpile_python_to_ruby(python_code)
print(ruby_code)
```

### Command Line
```bash
# Transpile a file
python3 -m tools.py2ruby script.py

# Specify output file
python3 -m tools.py2ruby script.py -o output.rb

# From stdin
echo "print('hello')" | python3 -m tools.py2ruby -
```

## Architecture Benefits

### Original Monolithic Design Issues
- Single 977-line file with multiple responsibilities
- Large configuration dictionaries mixed with logic
- Difficult to test individual components
- Hard to extend with new Python constructs
- Complex maintenance and debugging

### New Modular Design Benefits
- **Maintainability**: Each module < 200 lines with clear purpose
- **Testability**: Individual components can be unit tested
- **Extensibility**: Easy to add new Python construct handlers
- **Reusability**: Code generation utilities can be reused
- **Debugging**: Easier to isolate and fix issues

## File Size Reduction

| Original | New Modules | Lines | Purpose |
|----------|-------------|-------|---------|
| `py2ruby_transpiler.py` | `config.py` | 150 | Configuration mappings |
| (977 lines) | `code_generator.py` | 180 | Ruby code generation |
|  | `visitors.py` | 350 | Specialized AST visitors |
|  | `transpiler.py` | 200 | Main transpiler coordination |
|  | `__main__.py` | 100 | CLI interface |
|  | `__init__.py` | 25 | Package exports |
| **Total** | **6 modules** | **1005** | **Modular architecture** |

While the total line count is slightly higher due to better documentation and separation, each individual file is now manageable and focused.

## Testing

The modular design enables comprehensive unit testing:

```python
# Test individual components
from tools.py2ruby.config import MODULE_MAPPINGS
from tools.py2ruby.code_generator import RubyCodeGenerator
from tools.py2ruby.visitors import ImportVisitor

# Each module can be tested independently
```

## Migration from Original

The original `py2ruby_transpiler.py` is preserved for compatibility. To use the new modular version:

```python
# Old way
from tools.py2ruby_transpiler import PythonToRubyTranspiler

# New way
from tools.py2ruby import PythonToRubyTranspiler
```

The API remains compatible while providing better internal structure.

## Future Enhancements

The modular design makes it easy to add:

1. **New Python Constructs**: Add visitors for f-strings, walrus operator, etc.
2. **Better Ruby Idioms**: Enhance code generation for more idiomatic Ruby
3. **Type Hints**: Add support for Python type annotations
4. **Error Handling**: Improve error reporting and recovery
5. **Optimization**: Add Ruby code optimization passes

## Contributing

When adding new features:

1. **Configuration**: Add new mappings to `config.py`
2. **AST Handling**: Add new visitors to `visitors.py` or create specialized visitor classes
3. **Code Generation**: Add utilities to `code_generator.py`
4. **Testing**: Add unit tests for each module
5. **Documentation**: Update this README with new capabilities