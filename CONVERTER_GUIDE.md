# Ruby to Python Converter Guide

## Yes, It Works! 🎉

**Short Answer**: Yes, the converter works! Use `tools/ruby_to_python_converter.py` - it's the main, documented, and well-tested converter.

## The Right Script to Use

With 155+ Python scripts in the repo, here's the definitive answer:

### **Primary Tool**: `tools/ruby_to_python_converter.py`

This is the **official, documented converter** mentioned in the README.md. Use this one!

```bash
# Basic usage
python3 tools/ruby_to_python_converter.py modules/exploits/path/to/module.rb

# Specify output location
python3 tools/ruby_to_python_converter.py input.rb -o output.py

# Get help
python3 tools/ruby_to_python_converter.py --help
```

## Quick Start Example

### 1. Convert a Single Ruby Module

```bash
# Convert a Ruby exploit module to Python
python3 tools/ruby_to_python_converter.py modules/exploits/multi/http/example.rb
```

This generates a Python template with:
- ✅ Extracted metadata (name, description, authors, CVEs)
- ✅ Python module structure
- ✅ Logging setup
- ✅ Basic HTTP client scaffolding
- ✅ TODO comments for manual conversion steps

### 2. Example Output

Input Ruby module:
```ruby
class MetasploitModule < Msf::Exploit::Remote
  def initialize(info = {})
    super(update_info(info,
      'Name'           => 'Example HTTP Exploit',
      'Description'    => %q{
        This exploits a vulnerability in HTTP server.
      },
      'Author'         => ['John Doe <john@example.com>'],
      'License'        => MSF_LICENSE,
      'References'     =>
        [
          ['CVE', '2024-12345'],
          ['URL', 'https://example.com/advisory']
        ],
      'DisclosureDate' => '2024-01-15'
    ))
  end
  # ... rest of module
end
```

Output Python module:
```python
#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
Example HTTP Exploit

This exploits a vulnerability in HTTP server.
"""

import logging
import sys
import os

# Add lib path
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '../../../../lib'))

from metasploit import module
from msf.http_client import HTTPClient, CheckCode

metadata = {
    'name': 'Example HTTP Exploit',
    'description': '''
        This exploits a vulnerability in HTTP server.
    ''',
    'authors': [
        'John Doe <john@example.com>',
    ],
    'date': '2024-01-15',
    'license': 'MSF_LICENSE',
    'references': [
        {'type': 'cve', 'ref': '2024-12345'},
        {'type': 'url', 'ref': 'https://example.com/advisory'},
    ],
    'type': 'remote_exploit',  # TODO: Adjust type
    'options': {
        'rhost': {'type': 'address', 'description': 'Target address', 'required': True},
        'rport': {'type': 'port', 'description': 'Target port', 'required': True, 'default': 80},
        # TODO: Add module-specific options
    },
    'notes': {
        'stability': ['CRASH_SAFE'],  # TODO: Adjust
        'reliability': ['REPEATABLE_SESSION'],  # TODO: Adjust
        'side_effects': ['IOC_IN_LOGS']  # TODO: Adjust
    }
}

def run(args):
    '''Module entry point.'''
    module.LogHandler.setup(msg_prefix=f"{args['rhost']}:{args['rport']} - ")
    
    rhost = args['rhost']
    rport = args['rport']
    
    logging.info('Starting module execution...')
    
    # TODO: Implement module logic
    # 1. Create HTTP client or TCP socket
    # 2. Check if target is vulnerable
    # 3. Exploit the vulnerability
    # 4. Handle success/failure
    
    try:
        client = HTTPClient(rhost=rhost, rport=rport)
        
        # Your exploit code here
        response = client.get('/')
        if response:
            logging.info(f'Response status: {response.status_code}')
        
        client.close()
        
    except Exception as e:
        logging.error(f'Exploitation failed: {e}')
        return
    
    logging.info('Module execution complete')

if __name__ == '__main__':
    module.run(metadata, run)
```

## What About All Those Other Scripts?

The repo root has 155+ Python scripts due to the conversion project's evolution. Here's what they are:

### Categories of Scripts

1. **Official Tool** (USE THIS):
   - `tools/ruby_to_python_converter.py` - The main converter ✅

2. **Batch Conversion Scripts** (Historical - used during mass conversion):
   - `batch_ruby_to_python_converter.py` - Converts all post-2020 modules
   - `convert_exploits_now.py` - Batch exploit conversion
   - `batch_plugin_converter.py` - Plugin conversion
   - These were used to migrate the entire framework

3. **Wrapper/Runner Scripts** (Run the batch converter):
   - `run_converter.py`, `run_converter_main.py`, `convert_now.py`
   - `simple_conversion.py`, `direct_conversion_exec.py`
   - `execute_conversion.py`, `execute_converter_main.py`
   - `run_ruby_conversion.py`, etc.
   - These are different entry points for the same batch conversion

4. **Testing/Development Scripts**:
   - `test_convert.py`, `test_migration.py`, `direct_convert_test.py`
   - `manual_convert_test.py`, `simple_migration_test.py`
   - Used during development to test conversion logic

5. **Discovery/Analysis Scripts**:
   - `count_ruby_files.py`, `scan_ruby.py`, `quick_ruby_scan.py`
   - `find_ruby_files.py`, `run_discovery.py`
   - Analyze what needs to be converted

6. **Migration Management**:
   - `execute_migration.py`, `run_migration_now.py`, etc.
   - Various migration orchestration scripts

7. **Fun/Victory Scripts** 😄:
   - `PYTHON_VICTORY.py`, `RUBY_FAREWELL.py`
   - `fight_ruby_with_python.py`, `final_battle.py`
   - `ruby_killer_final.py`, `ultimate_ruby_killer.py`
   - Celebratory scripts marking milestones

## What the Converter Does

The converter (`tools/ruby_to_python_converter.py`) performs:

1. **Metadata Extraction**:
   - Module name, description, authors
   - CVE references, URLs
   - Disclosure date
   - Platform and target information
   - License

2. **Pattern Translation**:
   - String interpolation: `#{var}` → `{var}` (use f-strings)
   - Symbols to strings: `:symbol` → `'symbol'`
   - Booleans: `true`/`false`/`nil` → `True`/`False`/`None`
   - Hash rockets: `=>` → `:`
   - Control flow: `unless` → `if not`, `elsif` → `elif`
   - Print statements: `print_status` → `logging.info()`, etc.

3. **Template Generation**:
   - Python module header with proper encoding
   - Import statements
   - Metadata dictionary
   - Entry point function with logging
   - Placeholder for exploit logic
   - TODO comments for manual steps

## What You Still Need to Do Manually

The converter creates a **template** that you need to complete:

### Required Manual Steps:

1. **Implement Exploit Logic**:
   - Convert Ruby exploit code to Python
   - Adapt HTTP requests, socket operations
   - Handle payloads and encoding

2. **Convert Ruby-Specific Code**:
   - `pack`/`unpack` → `struct.pack`/`struct.unpack`
   - Ruby regex → Python regex
   - Ruby string methods → Python equivalents
   - Ruby blocks/iterators → Python loops

3. **Add Options**:
   - Module-specific configuration options
   - Default values
   - Validation logic

4. **Implement Check Function**:
   - Vulnerability detection logic
   - Return proper CheckCode values

5. **Error Handling**:
   - Proper exception handling
   - Cleanup on failure
   - Meaningful error messages

6. **Testing**:
   - Test against vulnerable targets
   - Verify all functionality works
   - Handle edge cases

## Conversion Patterns Reference

### Common Ruby → Python Translations

| Ruby | Python | Notes |
|------|--------|-------|
| `#{variable}` | `f"{variable}"` | Use f-strings |
| `:symbol` | `'symbol'` | Symbols become strings |
| `true`/`false`/`nil` | `True`/`False`/`None` | Capitalization |
| `=>` | `:` | Hash/dict syntax |
| `[data].pack('N')` | `struct.pack('>I', data)` | Network byte order |
| `str.unpack('C*')` | `list(str)` or `struct.unpack()` | Depends on context |
| `var.length` | `len(var)` | Function not method |
| `var.empty?` | `not var` or `var == ''` | Truthiness differs |
| `unless condition` | `if not condition` | Invert logic |
| `elsif` | `elif` | Spelling |
| `var.each { \|x\| }` | `for x in var:` | Loops |
| `print_status(msg)` | `logging.info(msg)` | Logging |
| `print_good(msg)` | `logging.info(msg)` | Success messages |
| `print_error(msg)` | `logging.error(msg)` | Error messages |
| `fail_with(...)` | `raise Exception(...)` | Error handling |
| `send_request_cgi({...})` | `client.get(...)` / `client.post(...)` | HTTP client |
| `connect` / `disconnect` | `socket.connect()` / `socket.close()` | Socket ops |

### Pack/Unpack Reference

Ruby's `pack` and `unpack` → Python's `struct.pack` and `struct.unpack`

| Ruby | Python | Description |
|------|--------|-------------|
| `'C'` | `'B'` | Unsigned char |
| `'S'` | `'H'` | Unsigned short (16-bit, native) |
| `'L'` | `'I'` | Unsigned long (32-bit, native) |
| `'n'` | `'>H'` | Unsigned short (16-bit, big-endian) |
| `'N'` | `'>I'` | Unsigned long (32-bit, big-endian) |
| `'v'` | `'<H'` | Unsigned short (16-bit, little-endian) |
| `'V'` | `'<I'` | Unsigned long (32-bit, little-endian) |
| `'Q'` | `'Q'` | Unsigned quad (64-bit, native) |
| `'q'` | `'q'` | Signed quad (64-bit, native) |
| `'c'` | `'c'` | Single character (char) |
| `'A'` | | Arbitrary binary string (null padded) |
| `'a'` | | Arbitrary binary string (space padded) |
| `'H'` | | Hex string (high nibble first) |
| `'h'` | | Hex string (low nibble first) |
| `'M'` | | Quoted-printable |
| `'m'` | | Base64 |

## Framework Integration

The generated Python modules integrate with the Python framework:

```python
# Framework structure
metasploit-framework-pynative/
├── lib/
│   ├── msf/                  # Python framework core
│   │   └── http_client.py    # HTTP client utilities
│   ├── metasploit/           # Module interface
│   │   └── module.py         # Module runner and logging
│   └── rex/                  # Protocol libraries
│
├── modules/
│   └── exploits/             # Python exploit modules
│       └── multi/
│           └── http/
│               └── your_exploit.py
```

## Frequently Asked Questions

### Q: Should I convert pre-2020 modules?
**A**: No, keep them in Ruby in `modules_legacy/`. Only convert post-2020 modules (DisclosureDate >= 2020-01-01).

### Q: Can the converter handle complex Ruby code?
**A**: It handles metadata extraction and basic patterns. Complex exploit logic requires manual conversion.

### Q: What if conversion fails?
**A**: The converter is best-effort. If it can't extract metadata, you'll get a basic template with TODOs.

### Q: Should I keep the Ruby original?
**A**: Yes, for reference during manual conversion. Move it to `modules_legacy/` when done.

### Q: How do I test the converted module?
**A**: Run it directly with Python: `python3 modules/exploits/path/to/module.py` (after completing manual steps).

## Getting Help

- See [PYTHON_CONVERSION_STRATEGY.md](PYTHON_CONVERSION_STRATEGY.md) for overall conversion strategy
- See [PYTHON_QUICKSTART.md](PYTHON_QUICKSTART.md) for Python module development guide
- See [PYTHON_TRANSLATIONS.md](PYTHON_TRANSLATIONS.md) for examples of converted modules
- Check `tools/ruby_to_python_converter.py` source code for implementation details

## Contributing Converted Modules

When submitting converted modules:

1. ✅ Use the converter to generate the initial template
2. ✅ Complete all TODO items manually
3. ✅ Test thoroughly against vulnerable targets
4. ✅ Follow Python coding standards (PEP 8)
5. ✅ Include docstrings and comments
6. ✅ Update metadata with accurate information
7. ✅ Add proper error handling
8. ✅ Document any limitations or requirements

## Summary

**Use `tools/ruby_to_python_converter.py` - it works great!**

The 155+ scripts in the root directory are from the mass conversion project. They're historical artifacts showing the evolution of converting the entire Metasploit Framework to Python. For converting individual modules, stick with the official tool.

Happy converting! 🐍
