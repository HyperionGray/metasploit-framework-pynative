# Python to Ruby Transpiler

This tool converts Python Metasploit modules back to Ruby format, maintaining compatibility with Ruby-based infrastructure and enabling bidirectional workflows.

## Features

- **Full Python AST support**: Parses and converts Python syntax accurately
- **Metasploit-compatible**: Generates valid MSF Ruby modules
- **Smart conversions**: Handles Python idioms and converts to Ruby equivalents
- **Comment preservation**: Maintains documentation and comments
- **Type hint removal**: Strips Python-specific type hints for clean Ruby code

## Usage

### Basic Conversion

```bash
# Convert a single Python module
python3 transpiler.py path/to/module.py -o output.rb

# Verbose mode
python3 transpiler.py input.py -o output.rb --verbose
```

### Batch Conversion

```bash
# Convert multiple files
for file in modules/exploits/linux/http/*.py; do
    python3 transpiler.py "$file" -o "${file%.py}.rb"
done
```

## Conversion Patterns

### Class Definitions

**Python:**
```python
class MetasploitModule(RemoteExploit, HttpExploitMixin):
    """My exploit module"""
    pass
```

**Ruby:**
```ruby
class MetasploitModule < Msf::Exploit::Remote
  include Msf::Exploit::Remote::HttpClient
  
  # My exploit module
end
```

### Method Definitions

**Python:**
```python
def exploit(self) -> ExploitResult:
    response = self.http_post('/api/admin', data={'cmd': payload})
    if response.status_code == 200:
        return ExploitResult(True, "Exploitation successful")
    return ExploitResult(False, "Exploitation failed")
```

**Ruby:**
```ruby
def exploit
  res = send_request_cgi({
    'method' => 'POST',
    'uri' => '/api/admin',
    'data' => {'cmd' => payload}
  })
  
  if res && res.code == 200
    return ExploitResult.new(true, "Exploitation successful")
  end
  ExploitResult.new(false, "Exploitation failed")
end
```

### String Formatting

**Python:**
```python
message = f"Connecting to {self.rhost}:{self.rport}"
self.print_status(message)
```

**Ruby:**
```ruby
message = "Connecting to #{rhost}:#{rport}"
print_status(message)
```

### Data Structures

**Python:**
```python
options = {
    'RHOSTS': {'required': True, 'description': 'Target host'},
    'RPORT': {'required': True, 'default': 80}
}
```

**Ruby:**
```ruby
options = {
  'RHOSTS' => {'required' => true, 'description' => 'Target host'},
  'RPORT' => {'required' => true, 'default' => 80}
}
```

## Options

- `-o, --output`: Output Ruby file path (required)
- `-v, --verbose`: Enable detailed logging
- `--preserve-types`: Keep type hints as comments
- `--format`: Run rubocop formatting on output

## Advanced Usage

### With MSF Environment

```bash
# Activate MSF environment
source msfrc

# Convert Python module to Ruby
python3 transpilers/py2ruby/transpiler.py \
    modules/exploits/linux/http/new_exploit.py \
    -o modules/exploits/linux/http/new_exploit.rb
```

### Integration with Framework

```python
from transpilers.py2ruby.transpiler import PythonToRubyTranspiler

transpiler = PythonToRubyTranspiler()
ruby_code = transpiler.convert_file('module.py')

# Save to file
with open('output.rb', 'w') as f:
    f.write(ruby_code)
```

## Conversion Strategy

### Type Hints

Python type hints are converted to Ruby comments:

**Python:**
```python
def check(self, target: str, port: int) -> bool:
```

**Ruby:**
```ruby
# @param target [String]
# @param port [Integer]
# @return [Boolean]
def check(target, port)
```

### Exception Handling

**Python:**
```python
try:
    response = self.http_get('/admin')
except ConnectionError as e:
    self.print_error(f"Connection failed: {e}")
    return False
```

**Ruby:**
```ruby
begin
  res = send_request_cgi('uri' => '/admin')
rescue ::Rex::ConnectionError => e
  print_error("Connection failed: #{e}")
  return false
end
```

### List Comprehensions

**Python:**
```python
ports = [p for p in range(1, 1025) if p % 2 == 0]
```

**Ruby:**
```ruby
ports = (1..1024).select { |p| p.even? }
```

## Known Limitations

1. **Advanced Python features**: Some Python 3.11+ features may need manual conversion
2. **Decorators**: Python decorators converted to Ruby class methods or comments
3. **Context managers**: `with` statements converted to `begin/ensure` blocks
4. **Async/await**: Async Python code needs manual conversion to Ruby threading

## Testing Converted Modules

After conversion, validate the Ruby module:

```bash
# Check Ruby syntax
ruby -c output.rb

# Run rubocop
rubocop output.rb

# Test with Metasploit
msfconsole -q -x "use exploit/path/to/output; check; exit"
```

## Troubleshooting

### Common Issues

**Syntax errors in Ruby output:**
- Review Python code for unsupported patterns
- Use `--verbose` to see conversion steps
- Check if Python features have Ruby equivalents

**Missing Ruby gems:**
```bash
# Install required gems
bundle install
```

**Type conversion issues:**
- Python integers → Ruby integers
- Python strings → Ruby strings
- Python lists → Ruby arrays
- Python dicts → Ruby hashes

## Best Practices

1. **Write clean Python**: Well-structured Python converts better
2. **Follow MSF patterns**: Use framework helpers consistently
3. **Test both versions**: Verify functionality in both languages
4. **Document differences**: Note any manual adjustments needed

## Contributing

When improving the transpiler:

1. Add test cases for Python→Ruby patterns
2. Document conversion strategies
3. Handle edge cases gracefully
4. Test on real Metasploit modules

## See Also

- [Main Transpilers README](../README.md)
- [PY2RUBY_TRANSPILER_GUIDE.md](../../PY2RUBY_TRANSPILER_GUIDE.md)
- [Ruby Framework Documentation](../../lib/msf/README.md)
