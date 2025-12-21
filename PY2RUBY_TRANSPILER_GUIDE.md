# Python to Ruby Transpiler 🐍 ➡️ 💎

## YES, We Built a Full Transpiler!

The `tools/py2ruby_transpiler.py` is a complete AST-based transpiler that converts Python code to Ruby code.

## Quick Start

```bash
# Transpile a Python file
python3 tools/py2ruby_transpiler.py script.py

# Specify output file
python3 tools/py2ruby_transpiler.py script.py -o output.rb

# Transpile from stdin
echo "print('hello')" | python3 tools/py2ruby_transpiler.py -

# Show Python AST for debugging
python3 tools/py2ruby_transpiler.py script.py --show-ast
```

## What It Can Transpile

### ✅ Fully Supported

**Control Flow:**
- `if/elif/else` → `if/elsif/else/end`
- `while` loops → `while/end`
- `for` loops → `.each do |var|/end`
- `range()` → Ruby ranges `(0...n)`
- `break` → `break`
- `continue` → `next`
- `pass` → `# pass`

**Functions & Classes:**
- Function definitions with default arguments
- `*args` and `**kwargs`
- Class definitions with inheritance
- `__init__` → `initialize`
- `__str__` → `to_s`
- `__len__` → `length`
- `self` → `self`

**Data Structures:**
- Lists `[1, 2, 3]` → Arrays `[1, 2, 3]`
- Dicts `{"key": "value"}` → Hashes `{key: "value"}`
- Tuples `(1, 2)` → Arrays `[1, 2]`
- Sets (converted to arrays)

**Operators:**
- Arithmetic: `+`, `-`, `*`, `/`, `%`, `**`
- Comparison: `==`, `!=`, `<`, `>`, `<=`, `>=`
- Logical: `and` → `&&`, `or` → `||`, `not` → `!`
- Bitwise: `&`, `|`, `^`, `<<`, `>>`

**String Operations:**
- f-strings `f"Hello {name}"` → `"Hello #{name}"`
- String methods: `upper()` → `upcase`, `lower()` → `downcase`
- `split()`, `strip()`, `replace()` → Ruby equivalents

**List/Array Operations:**
- `append()` → `push()`
- `extend()` → `concat()`
- `remove()` → `delete()`
- `sort()` → `sort!()`
- `reverse()` → `reverse!()`

**Comprehensions:**
- List comprehensions → `.map` and `.select`
  ```python
  [x**2 for x in numbers if x % 2 == 0]
  # ↓
  numbers.select { |x| x % 2 == 0 }.map { |x| x ** 2 }
  ```

- Dict comprehensions → `.map.to_h`
  ```python
  {k: v**2 for k, v in items.items()}
  # ↓
  items.to_a.map { |[k, v]| [k, v ** 2] }.to_h
  ```

**Exception Handling:**
- `try/except/else/finally` → `begin/rescue/else/ensure/end`
- Exception mapping (ValueError → ArgumentError, etc.)
- `raise` → `raise`

**Built-in Functions:**
- `len(x)` → `x.length`
- `print()` → `puts`
- `str()`, `int()`, `float()` → `.to_s`, `.to_i`, `.to_f`
- `isinstance()` → `.is_a?`
- `hasattr()` → `.respond_to?`

**Lambda Functions:**
- `lambda x: x + 1` → `lambda { |x| x + 1 }`

**Context Managers:**
- `with open(file) as f:` → `begin/ensure/end` pattern

### ⚠️ Partial Support (Needs Manual Review)

- Complex nested comprehensions
- Decorators (requires manual conversion)
- Generators (Ruby has Enumerators)
- Multiple inheritance (Ruby has mixins)
- `*args` unpacking in calls
- Slice syntax with step
- Metaclasses

### ❌ Not Supported (Manual Conversion Required)

- Type hints/annotations
- `async`/`await` (Ruby has fibers)
- `yield from`
- Walrus operator `:=`
- Pattern matching (Python 3.10+)
- Some advanced magic methods

## Live Demo

### Input Python Code:

```python
#!/usr/bin/env python3
"""HTTP Client Example"""

class HTTPClient:
    def __init__(self, host, port=80):
        self.host = host
        self.port = port
        self.connected = False
    
    def connect(self):
        print(f"Connecting to {self.host}:{self.port}")
        self.connected = True
        return True
    
    def get(self, path="/"):
        if not self.connected:
            raise RuntimeError("Not connected")
        
        request = f"GET {path} HTTP/1.1\r\n"
        return {"status": 200, "body": "OK"}
    
    def close(self):
        self.connected = False

def main():
    client = HTTPClient("example.com", 80)
    
    try:
        client.connect()
        response = client.get("/test")
        
        if response["status"] == 200:
            print("Success!")
        else:
            print(f"Failed: {response['status']}")
    except Exception as e:
        print(f"Error: {e}")
    finally:
        client.close()
    
    # List comprehension
    numbers = [1, 2, 3, 4, 5]
    squares = [x ** 2 for x in numbers if x % 2 == 0]
    print(f"Squares: {squares}")

if __name__ == "__main__":
    main()
```

### Generated Ruby Code:

```ruby
#!/usr/bin/env ruby
# -*- coding: utf-8 -*-

# Transpiled from Python to Ruby

'HTTP Client Example'

class HTTPClient
  def initialize(host, port = 80)
    self.host = host
    self.port = port
    self.connected = false
  end

  def connect
    puts "Connecting to #{self.host}:#{self.port}"
    self.connected = true
    return true
  end

  def get(path = '/')
    if !self.connected
      raise RuntimeError('Not connected')
    end
    request = "GET #{path} HTTP/1.1\r\n"
    return { status: 200, body: 'OK' }
  end

  def close
    self.connected = false
  end
end

def main
  client = HTTPClient.new('example.com', 80)
  
  begin
    client.connect()
    response = client.get('/test')
    
    if response[:status] == 200
      puts 'Success!'
    else
      puts "Failed: #{response[:status]}"
    end
  rescue StandardError => e
    puts "Error: #{e}"
  ensure
    client.close()
  end
  
  numbers = [1, 2, 3, 4, 5]
  squares = numbers.select { |x| x % 2 == 0 }.map { |x| x ** 2 }
  puts "Squares: #{squares}"
end

if __FILE__ == $0
  main()
end
```

## Translation Reference

### Python → Ruby Patterns

| Python | Ruby | Example |
|--------|------|---------|
| `None` | `nil` | `x = nil` |
| `True`/`False` | `true`/`false` | `flag = true` |
| `and`/`or`/`not` | `&&`/`\|\|`/`!` | `if x && !y` |
| `elif` | `elsif` | `elsif condition` |
| `pass` | `# pass` | `# pass` |
| `self` | `self` | `self.method` |
| `__init__` | `initialize` | `def initialize` |
| `len(x)` | `x.length` | `array.length` |
| `print(x)` | `puts x` | `puts "hello"` |
| `x.append(y)` | `x.push(y)` | `array.push(item)` |
| `x.upper()` | `x.upcase` | `string.upcase` |
| `range(5)` | `(0...5)` | `(0...5).each` |
| `for x in list:` | `list.each do \|x\|` | `list.each { \|x\| }` |
| `[x for x in list]` | `list.map { \|x\| x }` | `list.map(&:itself)` |
| `if x: return y` | `return y if x` | Postfix if |
| `f"{var}"` | `"#{var}"` | String interpolation |
| `try/except` | `begin/rescue` | Exception handling |
| `raise Error` | `raise Error` | Raise exception |
| `lambda x: x+1` | `lambda { \|x\| x+1 }` | Lambda function |
| `isinstance(x, T)` | `x.is_a?(T)` | Type checking |
| `hasattr(x, 'a')` | `x.respond_to?(:a)` | Attribute check |

### Method Mappings

**String Methods:**
- `.upper()` → `.upcase`
- `.lower()` → `.downcase`
- `.strip()` → `.strip`
- `.split()` → `.split`
- `.replace(a, b)` → `.gsub(a, b)`
- `.startswith(x)` → `.start_with?(x)`
- `.endswith(x)` → `.end_with?(x)`

**List/Array Methods:**
- `.append(x)` → `.push(x)` or `.<<(x)`
- `.extend(x)` → `.concat(x)`
- `.remove(x)` → `.delete(x)`
- `.pop()` → `.pop`
- `.index(x)` → `.index(x)`
- `.count(x)` → `.count(x)`
- `.sort()` → `.sort!`
- `.reverse()` → `.reverse!`

**Dict/Hash Methods:**
- `.keys()` → `.keys`
- `.values()` → `.values`
- `.items()` → `.to_a` (array of [k,v] pairs)
- `.get(k, default)` → `.fetch(k, default)`
- `.update(other)` → `.merge!(other)`

**Type Conversions:**
- `str(x)` → `x.to_s`
- `int(x)` → `x.to_i`
- `float(x)` → `x.to_f`
- `list(x)` → `x.to_a`
- `dict(x)` → `x.to_h`

## How It Works

The transpiler uses Python's `ast` (Abstract Syntax Tree) module to:

1. **Parse** Python code into an AST
2. **Traverse** the AST using the Visitor pattern
3. **Convert** each Python construct to Ruby equivalent
4. **Generate** syntactically correct Ruby code

### Architecture

```
Python Source Code
      ↓
   ast.parse()
      ↓
  Python AST
      ↓
PythonToRubyTranspiler
  (AST Visitor)
      ↓
  Ruby Code
```

### Key Components

- `visit_Module()` - Top-level module
- `visit_FunctionDef()` - Function definitions
- `visit_ClassDef()` - Class definitions
- `visit_If/While/For()` - Control flow
- `visit_Try()` - Exception handling
- `visit_expr()` - Expression dispatcher
- `visit_Call()` - Function calls
- `visit_BinOp()` - Binary operations
- `visit_Compare()` - Comparisons
- `visit_ListComp()` - List comprehensions

## Testing the Transpiler

### Simple Test

```bash
# Create test file
echo "print('Hello, World!')" > test.py

# Transpile
python3 tools/py2ruby_transpiler.py test.py

# Result: test.rb
# puts 'Hello, World!'
```

### Complex Test

```bash
# Transpile a real Python module
python3 tools/py2ruby_transpiler.py modules/some_module.py -o modules/some_module.rb

# Review the output
less modules/some_module.rb

# Test the Ruby code
ruby modules/some_module.rb
```

## Important Notes

### ⚠️ Always Review Output

The transpiler is **best-effort**. Always:
1. ✅ Review generated Ruby code
2. ✅ Test functionality
3. ✅ Check edge cases
4. ✅ Verify library calls
5. ✅ Add missing `require` statements
6. ✅ Fix Ruby syntax issues if any
7. ✅ Optimize for idiomatic Ruby

### Common Issues

**1. Attribute Assignment:**
Python: `self.x = 5`
Ruby: Needs `attr_accessor` or setter method

**2. List Slicing:**
Python: `list[1:3]`
Ruby: `list[1..2]` or `list[1...3]`

**3. String Formatting:**
Python: `"Value: %s" % val`
Ruby: `"Value: #{val}"` or `"Value: %s" % val`

**4. Module Imports:**
Python: `import requests`
Ruby: `require 'httparty'` (different library)

**5. Dictionary Access:**
Python: `dict["key"]`
Ruby: `hash[:key]` or `hash["key"]` (symbols vs strings)

## Use Cases

### 1. Porting Python Tools to Ruby

```bash
python3 tools/py2ruby_transpiler.py python_tool.py -o ruby_tool.rb
```

### 2. Converting Test Code

```bash
python3 tools/py2ruby_transpiler.py tests/test_module.py -o spec/module_spec.rb
```

### 3. Migrating Python Modules

```bash
python3 tools/py2ruby_transpiler.py lib/python/module.py -o lib/ruby/module.rb
```

### 4. Quick Prototyping

```bash
# Write logic in Python (faster)
# Transpile to Ruby (deployment target)
python3 tools/py2ruby_transpiler.py prototype.py -o production.rb
```

## Comparison with ruby2python Converter

| Feature | ruby2python | py2ruby |
|---------|-------------|---------|
| **Purpose** | Convert Ruby Metasploit modules to Python | Convert any Python code to Ruby |
| **Method** | Regex + Template generation | Full AST-based transpilation |
| **Scope** | Metasploit modules | General Python code |
| **Output** | Python template with TODOs | Complete Ruby code |
| **Accuracy** | Metadata extraction | Syntax conversion |
| **Use Case** | Module migration | General transpilation |

Both tools complement each other:
- Use **ruby2python** for Metasploit module migration
- Use **py2ruby** for general Python→Ruby conversion

## Advanced Usage

### Batch Transpilation

```bash
# Transpile all Python files in a directory
for file in *.py; do
    python3 tools/py2ruby_transpiler.py "$file"
done
```

### Pipeline Usage

```bash
# Combine with other tools
cat input.py | python3 tools/py2ruby_transpiler.py - | ruby-beautify > output.rb
```

### Debug Mode

```bash
# Show Python AST for debugging
python3 tools/py2ruby_transpiler.py script.py --show-ast
```

## Limitations

The transpiler handles **syntax conversion** well, but:

- ❌ Cannot convert Python-specific libraries (requests, numpy, etc.)
- ❌ Cannot handle all Python semantics (duck typing differences)
- ❌ May need manual optimization for performance
- ❌ Doesn't understand business logic context

**Bottom line:** Use it to save time on syntax conversion, but always review and test!

## Contributing

Found a Python construct that doesn't transpile well? 

1. Create a test case
2. Add the pattern to the transpiler
3. Update the documentation
4. Submit a PR

## Summary

✅ **Full AST-based transpiler**
✅ **Handles classes, functions, control flow**
✅ **Converts comprehensions**
✅ **Maps built-in functions**
✅ **Exception handling**
✅ **String interpolation**
✅ **Type conversions**
✅ **Lambda functions**

⚠️ **Always review output**
⚠️ **Test thoroughly**
⚠️ **Manual fixes may be needed**

**Use it to save hours of manual conversion work!** 🚀
