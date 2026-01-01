# Code Quality & Architecture Guide

## Overview

This guide provides architectural guidelines, code quality standards, and best practices for contributing to the Metasploit Framework Python-Native fork.

## Architecture Overview

### Repository Structure

```
metasploit-framework-pynative/
├── lib/                    # Core framework libraries
│   ├── msf/               # Metasploit framework core
│   │   ├── core/         # Core framework classes
│   │   ├── base/         # Base classes for modules
│   │   └── ui/           # User interface components
│   └── rex/               # Ruby Extension Library (now Python)
│       ├── socket/       # Socket abstractions
│       ├── proto/        # Protocol implementations
│       ├── encoder/      # Encoders
│       └── binary_analysis/  # Binary analysis tools
├── modules/               # Active modules (post-2020)
│   ├── exploits/         # Exploit modules
│   ├── auxiliary/        # Auxiliary modules
│   ├── payloads/         # Payload modules
│   ├── encoders/         # Encoder modules
│   └── post/            # Post-exploitation modules
├── modules_legacy/        # Legacy modules (pre-2020)
├── tools/                # Standalone tools
├── scripts/              # Meterpreter and other scripts
├── data/                 # Data files (templates, wordlists)
├── test/                 # Python tests
├── spec/                 # RSpec tests (legacy)
└── docs/                 # Documentation
```

### Design Principles

1. **Modularity**: Each module should be self-contained
2. **Reusability**: Common functionality in shared libraries
3. **Extensibility**: Easy to add new modules and features
4. **Security-First**: Security considerations in all design decisions
5. **Compatibility**: Maintain compatibility with original MSF concepts
6. **Python-First**: Leverage Python's strengths and ecosystem

## Code Quality Standards

### Linting and Formatting

#### Black - Code Formatter

```bash
# Format code
black lib/ modules/ tools/ --line-length 120

# Check formatting
black lib/ modules/ tools/ --check --line-length 120
```

Configuration in `pyproject.toml`:
```toml
[tool.black]
line-length = 120
target-version = ['py311']
```

#### isort - Import Sorting

```bash
# Sort imports
isort lib/ modules/ tools/

# Check import sorting
isort lib/ modules/ tools/ --check
```

Configuration in `pyproject.toml`:
```toml
[tool.isort]
profile = "black"
line_length = 120
```

#### Flake8 - Style Checker

```bash
# Check code style
flake8 lib/ modules/ tools/
```

Configuration in `.flake8`:
```ini
[flake8]
max-line-length = 120
ignore = E203, W503, E501
```

#### MyPy - Type Checker (Optional)

```bash
# Type check
mypy lib/ --ignore-missing-imports
```

### Running All Quality Checks

```bash
# Format code
black lib/ modules/ tools/ --line-length 120
isort lib/ modules/ tools/

# Check code
flake8 lib/ modules/ tools/
pytest --cov=lib --cov=modules
```

## Coding Standards

### Python Style Guide

Follow [PEP 8](https://peps.python.org/pep-0008/) with these modifications:

- **Line Length**: 120 characters (not 79)
- **Quotes**: Double quotes preferred for strings
- **Imports**: Use isort configuration
- **Naming**: See below

### Naming Conventions

```python
# Classes: PascalCase
class ExploitModule:
    pass

# Functions/Methods: snake_case
def execute_exploit():
    pass

# Constants: UPPER_CASE
MAX_RETRIES = 3

# Private/Internal: _leading_underscore
def _internal_helper():
    pass

# Protected: _leading_underscore (by convention)
class MyClass:
    def __init__(self):
        self._protected_attribute = None
```

### Module Structure

#### Exploit Module Template

```python
"""
Module description and metadata
"""

from lib.msf.core.exploit import Exploit
from lib.msf.core.handler import ReverseHttps


class MetasploitModule(Exploit):
    """Brief description of what this exploit does"""
    
    def __init__(self):
        super().__init__()
        self.update_info({
            'Name': 'Descriptive Exploit Name',
            'Description': '''
                Detailed description of the vulnerability
                and what this exploit does.
            ''',
            'Author': [
                'Original Discoverer',
                'Module Author <email@example.com>'
            ],
            'License': 'MSF_LICENSE',
            'References': [
                ['CVE', '2024-1234'],
                ['URL', 'https://example.com/advisory'],
            ],
            'Platform': ['windows', 'linux'],
            'Targets': [
                ['Windows 10', {'Ret': 0x12345678}],
                ['Ubuntu 20.04', {'Ret': 0x87654321}],
            ],
            'DefaultTarget': 0,
            'Notes': {
                'Stability': ['CRASH_SAFE'],
                'Reliability': ['REPEATABLE_SESSION'],
                'SideEffects': ['IOC_IN_LOGS'],
            }
        })
        
        self.register_options([
            ('RHOST', {'required': True, 'description': 'Target host'}),
            ('RPORT', {'required': True, 'default': 80, 'description': 'Target port'}),
        ])
    
    def check(self):
        """Check if target is vulnerable"""
        # Implement vulnerability check
        return 'appears'  # or 'safe' or 'vulnerable'
    
    def exploit(self):
        """Execute the exploit"""
        # Implement exploit logic
        pass
```

### Documentation Standards

#### Module Docstrings

```python
"""
Brief one-line summary.

Detailed description of the module, class, or function.
Explain what it does, how it works, and any important notes.

Args:
    param1: Description of first parameter
    param2: Description of second parameter

Returns:
    Description of return value

Raises:
    ExceptionType: When and why this exception is raised

Example:
    >>> obj = MyClass()
    >>> obj.method()
    'result'
"""
```

#### Inline Comments

```python
# Good: Explain WHY, not WHAT
# Use a larger buffer to prevent overflow in edge cases
buffer_size = original_size * 2

# Bad: Explain obvious code
# Increment counter by 1
counter += 1
```

### Error Handling

```python
# Good: Specific exceptions with context
try:
    result = risky_operation()
except ConnectionError as e:
    self.print_error(f"Connection failed: {e}")
    return False
except ValueError as e:
    self.print_error(f"Invalid value: {e}")
    return False
except Exception as e:
    self.print_error(f"Unexpected error: {e}")
    return False

# Bad: Bare except catching everything
try:
    result = risky_operation()
except:
    pass
```

### Logging and Output

```python
# Use framework logging methods
self.print_status("Starting exploit...")
self.print_good("Exploit successful!")
self.print_error("Connection failed")
self.print_warning("Target may not be vulnerable")

# For debug output
self.vprint_status("Detailed debug info")  # Only shown in verbose mode
```

## Architecture Patterns

### Module Base Classes

```python
# Exploit modules inherit from Exploit
from lib.msf.core.exploit import Exploit

class MetasploitModule(Exploit):
    pass

# Auxiliary modules inherit from Auxiliary
from lib.msf.core.auxiliary import Auxiliary

class MetasploitModule(Auxiliary):
    pass

# Payload modules inherit from Payload
from lib.msf.core.payload import Payload

class MetasploitModule(Payload):
    pass
```

### Mixins for Common Functionality

```python
# HTTP client functionality
from lib.msf.core.exploit.http_client import HttpClient

class MetasploitModule(Exploit, HttpClient):
    def exploit(self):
        # HTTP methods available: send_request_cgi, send_request_raw, etc.
        response = self.send_request_cgi({
            'uri': '/vulnerable/path',
            'method': 'GET',
        })
```

### Option Registration

```python
self.register_options([
    ('RHOST', {
        'required': True,
        'description': 'Target host'
    }),
    ('RPORT', {
        'required': True,
        'default': 80,
        'description': 'Target port'
    }),
    ('SSL', {
        'required': False,
        'default': False,
        'description': 'Use SSL/TLS'
    }),
])

# Advanced options
self.register_advanced_options([
    ('TIMEOUT', {
        'default': 30,
        'description': 'Connection timeout in seconds'
    }),
])
```

## Performance Considerations

### Efficient Code

```python
# Good: Use list comprehensions
results = [process(item) for item in items if condition(item)]

# Good: Use generators for large datasets
def process_large_file(filename):
    with open(filename) as f:
        for line in f:  # Generator, not loading all into memory
            yield process_line(line)

# Good: Cache expensive operations
from functools import lru_cache

@lru_cache(maxsize=128)
def expensive_computation(param):
    return complex_calculation(param)
```

### Avoid Common Pitfalls

```python
# Bad: Inefficient string concatenation in loops
result = ""
for item in items:
    result += str(item)  # Creates new string each time

# Good: Use join
result = "".join(str(item) for item in items)

# Bad: Checking membership in list repeatedly
if item in my_list:  # O(n) operation
    pass

# Good: Use set for membership testing
my_set = set(my_list)
if item in my_set:  # O(1) operation
    pass
```

## Dependency Management

### Adding Dependencies

1. Check if functionality exists in standard library first
2. Check if functionality exists in existing dependencies
3. If new dependency needed:
   - Add to `requirements.txt`
   - Justify in PR description
   - Consider license compatibility
   - Check for security vulnerabilities

```bash
# Check package
pip show package-name

# Install package
pip install package-name

# Update requirements.txt
pip freeze | grep package-name >> requirements.txt
```

## Code Review Checklist

Before submitting code:

- [ ] Code follows Python style guide (PEP 8 with our modifications)
- [ ] Code is formatted with Black and isort
- [ ] Code passes Flake8 checks
- [ ] All functions/classes have docstrings
- [ ] Tests are written and pass
- [ ] No security vulnerabilities (see SECURITY_BEST_PRACTICES.md)
- [ ] No hardcoded credentials or secrets
- [ ] Error handling is appropriate
- [ ] Logging uses framework methods
- [ ] Dependencies are justified and documented
- [ ] Code is efficient and doesn't have obvious performance issues

## Tools and Resources

### Development Tools

```bash
# Install development dependencies
pip install -r requirements.txt
pip install black isort flake8 mypy pytest pytest-cov

# Pre-commit hook (optional)
pip install pre-commit
pre-commit install
```

### Useful Resources

- [PEP 8 Style Guide](https://peps.python.org/pep-0008/)
- [Python Documentation](https://docs.python.org/3/)
- [Effective Python](https://effectivepython.com/)
- [Clean Code in Python](https://github.com/zedr/clean-code-python)

## Questions and Support

For architecture or code quality questions:
- Review [CODE_QUALITY.md](../CODE_QUALITY.md)
- Check existing code for examples
- Ask in GitHub Discussions
- Join Metasploit Slack

---

Last updated: 2025-12-28
