# Ruby to Python Conversion Tools

This directory contains the essential tools for converting Ruby Metasploit modules to Python.

## Directory Structure

```
ruby2py/
├── convert.py        # Main Ruby→Python converter (runnable)
├── py2ruby/          # Python→Ruby transpiler (reverse conversion)
├── deprecated/       # Old conversion scripts (kept for reference)
└── README.md         # This file
```

## Quick Start

### Convert Ruby Module to Python

The main converter is `convert.py` - this is the tool you want to use:

```bash
# Convert a single Ruby module
python3 ruby2py/convert.py path/to/module.rb

# Specify output file
python3 ruby2py/convert.py input.rb -o output.py

# Verbose mode
python3 ruby2py/convert.py input.rb --verbose
```

### Batch Conversion

```bash
# Convert entire directory
python3 ruby2py/convert.py modules/exploits/linux/http/ --recursive

# With pattern matching
python3 ruby2py/convert.py modules/ --pattern "*.rb" --recursive
```

## Features

- **AST-based parsing**: Uses Ruby AST for accurate conversion
- **Metasploit-aware**: Handles MSF-specific patterns and DSL
- **Type hints**: Generates Python type hints for better code quality
- **Automatic imports**: Manages Python import statements
- **Preserves structure**: Maintains module organization and metadata

## Conversion Patterns

### Class Definitions

**Ruby:**
```ruby
class MetasploitModule < Msf::Exploit::Remote
  include Msf::Exploit::Remote::HttpClient
end
```

**Python:**
```python
class MetasploitModule(RemoteExploit, HttpExploitMixin):
    """Converted from Ruby"""
```

### Method Definitions

**Ruby:**
```ruby
def check
  res = send_request_cgi('uri' => '/test')
  return CheckCode::Vulnerable if res && res.code == 200
  CheckCode::Safe
end
```

**Python:**
```python
def check(self) -> ExploitResult:
    res = self.http_get('/test')
    if res and res.status_code == 200:
        return CheckCode.VULNERABLE
    return CheckCode.SAFE
```

### String Interpolation

**Ruby:**
```ruby
print_status("Connecting to #{rhost}:#{rport}")
```

**Python:**
```python
self.print_status(f"Connecting to {self.rhost}:{self.rport}")
```

## Options

- `-o, --output`: Specify output file path
- `-r, --recursive`: Process directories recursively
- `-v, --verbose`: Enable detailed logging
- `--dry-run`: Show what would be converted without writing files
- `--pattern`: File pattern for recursive mode (default: `*.rb`)

## Advanced Usage

### With MSF Environment

```bash
# Activate MSF environment first
source msfrc

# Convert module
python3 ruby2py/convert.py modules/exploits/windows/smb/old_exploit.rb
```

### Integration with Framework

```python
from ruby2py.convert import RubyToPythonConverter

converter = RubyToPythonConverter()
python_code = converter.convert_file('module.rb')
```

## Known Limitations

1. **Complex metaprogramming**: Advanced Ruby metaprogramming may need manual adjustment
2. **External dependencies**: Ruby gems need Python equivalents
3. **Binary data**: Some binary operations may differ between languages

## Testing Converted Modules

After conversion, test the module:

```bash
# Check syntax
python3 -m py_compile output.py

# Run module checks
python3 output.py --check-only --host target.example.com

# Full test
python3 -m pytest test_converted_module.py
```

## Troubleshooting

### Common Issues

**Import errors:**
```bash
# Install required Python packages
pip3 install -r requirements.txt
```

**Syntax errors in output:**
- Use `--verbose` to see conversion details
- Review Ruby code for unsupported patterns
- File an issue with problematic code snippet

**Missing functionality:**
- Check if Ruby gem has Python equivalent
- Review Python framework helper modules
- May need manual implementation

## Contributing

When improving the converter:

1. Add test cases for new patterns
2. Document Ruby→Python mappings
3. Update conversion statistics
4. Test on real Metasploit modules

## Deprecated Scripts

The `deprecated/` directory contains old conversion scripts that are kept for reference only. 
These scripts have been superseded by `convert.py` and should not be used for new conversions.

## See Also

- [Conversion Documentation](../docs/ruby2py/) - Detailed conversion guides and strategies
- [Python Framework Documentation](../python_framework/README.md) - Python module framework
