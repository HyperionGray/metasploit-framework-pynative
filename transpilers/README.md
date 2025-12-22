# Metasploit Framework Transpilers

This directory contains bidirectional transpilation tools for converting between Ruby and Python code in the Metasploit Framework.

## Directory Structure

```
transpilers/
├── ruby2py/     # Ruby to Python transpiler
│   ├── converter.py
│   └── README.md
├── py2ruby/     # Python to Ruby transpiler
│   ├── transpiler.py
│   └── README.md
└── README.md    # This file
```

## Purpose

As the Metasploit team continues to collect exploits from contributors, these transpilers enable:

1. **Ruby → Python conversion**: Modernize legacy Ruby modules to Python
2. **Python → Ruby conversion**: Maintain compatibility with Ruby-based infrastructure
3. **Bidirectional workflow**: Seamlessly work between both languages during transition

## Quick Start

### Ruby to Python Conversion

Convert a Ruby module to Python:

```bash
# Convert a single Ruby file
python3 transpilers/ruby2py/converter.py modules/exploits/windows/smb/example.rb

# Convert with output path
python3 transpilers/ruby2py/converter.py input.rb -o output.py

# Batch convert directory
python3 transpilers/ruby2py/converter.py modules/exploits/linux/http/ --recursive
```

### Python to Ruby Conversion

Convert a Python module back to Ruby:

```bash
# Convert a single Python file
python3 transpilers/py2ruby/transpiler.py modules/exploits/linux/http/example.py -o output.rb

# Convert with options
python3 transpilers/py2ruby/transpiler.py script.py -o output.rb --verbose
```

## Features

### Ruby to Python Transpiler

- AST-based parsing and conversion
- Preserves module metadata and structure
- Converts Metasploit-specific patterns
- Handles Ruby idioms (symbols, blocks, mixins)
- Type hint generation
- Automatic import management

### Python to Ruby Transpiler

- Full Python AST support
- Converts Python idioms to Ruby equivalents
- Maintains Metasploit Framework compatibility
- Preserves comments and documentation
- Smart string interpolation conversion

## Use Cases

### For Module Developers

- **Modernize old exploits**: Convert pre-2020 Ruby modules to Python
- **Maintain compatibility**: Generate Ruby versions of Python modules for legacy systems
- **Learn by example**: See how Ruby patterns translate to Python

### For Framework Maintainers

- **Batch migration**: Convert entire directories of modules
- **Testing**: Generate Ruby versions to test compatibility
- **Documentation**: Create parallel examples in both languages

## Integration with MSF Workflow

These transpilers are designed to work seamlessly with the Metasploit Framework:

```bash
# Activate MSF environment (like Python virtualenv)
source msfrc

# Now transpiler commands are in your PATH
cd modules/exploits/
python3 ../../transpilers/ruby2py/converter.py windows/smb/old_module.rb
```

## Technical Details

### Supported Ruby Patterns

- Class definitions and inheritance
- Module mixins
- Method definitions
- Instance variables
- String interpolation
- Symbols and hashes
- Blocks and procs
- Metasploit DSL (register_options, etc.)

### Supported Python Patterns

- Class definitions with multiple inheritance
- Type hints and annotations
- F-strings and string formatting
- Dictionaries and data structures
- Decorators and context managers
- Metasploit Python framework patterns

## Testing

Both transpilers include test suites:

```bash
# Test Ruby to Python transpiler
python3 -m pytest transpilers/ruby2py/tests/

# Test Python to Ruby transpiler
python3 -m pytest transpilers/py2ruby/tests/
```

## Contributing

When contributing exploits or modules:

1. **New modules**: Write in Python (preferred)
2. **Legacy modules**: Use ruby2py transpiler for conversion
3. **Compatibility needed**: Generate Ruby version with py2ruby

## Documentation

- [Ruby to Python Converter Guide](ruby2py/README.md)
- [Python to Ruby Transpiler Guide](py2ruby/README.md)
- [CONVERTER_GUIDE.md](../CONVERTER_GUIDE.md) - Detailed conversion guide
- [PY2RUBY_TRANSPILER_GUIDE.md](../PY2RUBY_TRANSPILER_GUIDE.md) - Detailed transpilation guide

## Maintenance

These transpilers are actively maintained as the MSF team continues to collect exploits. Report issues or suggest improvements via GitHub Issues.

## License

These tools are part of the Metasploit Framework and released under the same BSD-style license.
