# Code Quality Guidelines for Metasploit Framework

This document outlines code quality standards, best practices, and guidelines for maintaining high-quality code in the Metasploit Framework.

## Table of Contents

- [Overview](#overview)
- [Code Style](#code-style)
- [Code Comments and Documentation](#code-comments-and-documentation)
- [TODO and FIXME Comments](#todo-and-fixme-comments)
- [Error Handling](#error-handling)
- [Security Best Practices](#security-best-practices)
- [Code Review Process](#code-review-process)
- [Tools and Automation](#tools-and-automation)

## Overview

Maintaining high code quality is essential for the Metasploit Framework. Quality code is:

- **Readable**: Easy to understand and follow
- **Maintainable**: Easy to modify and extend
- **Testable**: Easy to write tests for
- **Secure**: Free from vulnerabilities
- **Performant**: Efficient and scalable
- **Well-documented**: Clear explanations and examples

## Code Style

### Python Style Guide

Follow the [PEP 8 Style Guide](https://www.python.org/dev/peps/pep-0008/) with some modifications:

```python
# Line length: 120 characters (configured in pyproject.toml)
# Use Black for automatic formatting
# Use isort for import sorting
```

#### Key Style Points

1. **Naming Conventions**

```python
# Classes: PascalCase
class ExploitModule:
    pass

# Functions and variables: snake_case
def load_module(module_name):
    exploit_path = get_path(module_name)
    return exploit_path

# Constants: UPPER_SNAKE_CASE
DEFAULT_TIMEOUT = 30
MAX_RETRIES = 3

# Private methods/attributes: leading underscore
class MyClass:
    def _private_method(self):
        pass
    
    def __init__(self):
        self._private_attr = None
```

2. **Import Organization**

```python
# Standard library imports
import os
import sys
from typing import Dict, List, Optional

# Third-party imports
import requests
from cryptography.fernet import Fernet

# Local application imports
from lib.msf.core import Framework
from lib.msf.base.exploit import Exploit
```

3. **Code Formatting**

```bash
# Format code with Black
python3 -m black lib/ modules/

# Sort imports with isort
python3 -m isort lib/ modules/

# Check with flake8
python3 -m flake8 lib/ modules/
```

### Ruby Style Guide

For legacy Ruby code, follow the [Ruby Style Guide](https://github.com/bbatsov/ruby-style-guide):

```ruby
# Use 2 spaces for indentation
# Use snake_case for methods and variables
# Use CamelCase for classes and modules
# Run rubocop for linting
bundle exec rubocop
```

## Code Comments and Documentation

### When to Write Comments

✅ **DO write comments for:**

- Complex algorithms or logic
- Non-obvious design decisions
- Security considerations
- Workarounds for bugs in external libraries
- Public APIs and interfaces

❌ **DON'T write comments for:**

- Obvious code (let the code speak for itself)
- Redundant descriptions of what code does
- Commented-out code (use version control instead)

### Good vs. Bad Comments

```python
# ❌ BAD: Redundant comment
# Increment counter by 1
counter += 1

# ✅ GOOD: Explains WHY, not WHAT
# Increment counter to track retries for exponential backoff
counter += 1

# ❌ BAD: Commented-out code
# old_method()
# legacy_approach()
new_method()

# ✅ GOOD: Explain non-obvious logic
# Use base64 encoding to avoid null bytes in payload
# which would terminate the string in C-style functions
encoded_payload = base64.b64encode(payload)
```

### Docstrings

Use docstrings for all public modules, classes, and functions:

```python
def exploit_target(target_host: str, target_port: int, payload: bytes) -> bool:
    """
    Exploit the target system with the provided payload.
    
    This function sends a crafted payload to the target system to
    trigger a buffer overflow in the vulnerable service.
    
    Args:
        target_host: IP address or hostname of the target
        target_port: Port number of the vulnerable service
        payload: Binary payload to execute on the target
    
    Returns:
        True if exploitation was successful, False otherwise
    
    Raises:
        ConnectionError: If unable to connect to target
        ValueError: If payload is invalid or too large
    
    Example:
        >>> payload = generate_payload('windows/meterpreter/reverse_tcp')
        >>> exploit_target('192.168.1.100', 445, payload)
        True
    """
    # Implementation here
    pass
```

### Module Documentation

All modules should include comprehensive documentation:

```python
"""
Exploit Module for CVE-2024-XXXXX - Example Vulnerability

This module exploits a buffer overflow vulnerability in Example Service 1.0
to execute arbitrary code on the target system.

Module Metadata:
    Name: Example Service Buffer Overflow
    Type: remote_exploit
    Platform: Windows, Linux
    Targets: Example Service 1.0-1.5
    CVE: CVE-2024-XXXXX
    References:
        - https://example.com/advisory
        - https://github.com/example/poc

Author: Your Name <your.email@example.com>
License: BSD 3-Clause

Usage:
    use exploit/multi/example_service_overflow
    set RHOSTS 192.168.1.100
    set RPORT 9999
    exploit

Verification Steps:
    1. Start a vulnerable Example Service instance
    2. Configure the module with target IP and port
    3. Run the exploit
    4. Verify you receive a Meterpreter session
"""
```

## TODO and FIXME Comments

### Purpose of TODO/FIXME Comments

TODO and FIXME comments help track technical debt and future improvements:

- **TODO**: Indicates a feature or improvement that should be added
- **FIXME**: Indicates a known bug or issue that needs to be fixed

### Guidelines for TODO/FIXME Comments

✅ **DO:**

```python
# TODO(username): Add support for IPv6 addresses
# Expected completion: Q1 2025
# Tracked in: #12345

# FIXME(username): Race condition when handling concurrent connections
# Workaround: Limit to single connection for now
# Tracked in: #12346
```

❌ **DON'T:**

```python
# TODO: Fix this
# FIXME: Broken

# TODO: Make this better
# TODO: Implement module logic  (too vague)
```

### Best Practices

1. **Include Context**: Explain what needs to be done and why
2. **Add Attribution**: Include your username/email
3. **Link to Issues**: Reference GitHub issues if applicable
4. **Set Expectations**: Indicate priority or timeline if known
5. **Remove When Done**: Delete TODO/FIXME once addressed
6. **Don't Commit Dead Code**: Remove commented-out code instead of leaving TODO comments

### Example Template

```python
# TODO(username): Brief description of what needs to be done
# Reason: Why this is needed or what problem it solves
# Priority: High/Medium/Low
# Issue: #12345
# Notes: Any additional context or considerations

# FIXME(username): Description of the bug or issue
# Impact: What functionality is affected
# Workaround: Temporary solution (if any)
# Root Cause: Known or suspected cause
# Issue: #12346
```

### Periodic Review

- Review TODO/FIXME comments quarterly
- Create GitHub issues for important items
- Remove obsolete comments
- Update progress on tracked items

## Error Handling

### Exception Handling Best Practices

```python
# ✅ GOOD: Specific exception handling
try:
    response = requests.get(url, timeout=10)
    response.raise_for_status()
except requests.Timeout:
    print_error("Connection timed out")
    return None
except requests.ConnectionError:
    print_error("Failed to connect to target")
    return None
except requests.HTTPError as e:
    print_error(f"HTTP error: {e.response.status_code}")
    return None

# ❌ BAD: Catching all exceptions
try:
    response = requests.get(url)
except Exception:
    pass  # Silent failure
```

### Metasploit-Specific Error Handling

```python
# Use Metasploit's print methods for console output
from lib.msf.core.ui import print_error, print_warning, print_status, print_good

def exploit():
    try:
        print_status("Attempting exploitation...")
        result = perform_exploit()
        print_good("Exploitation successful!")
        return result
    except ConnectionError as e:
        print_error(f"Connection failed: {e}")
        return None
    except ValueError as e:
        print_warning(f"Invalid configuration: {e}")
        return None
    finally:
        # Clean up resources
        cleanup_resources()
```

## Security Best Practices

### Input Validation

```python
# ✅ GOOD: Validate all user input
def set_target_host(host: str) -> bool:
    """Set the target host with validation."""
    # Validate IP address or hostname
    if not is_valid_host(host):
        print_error("Invalid host format")
        return False
    
    # Check for injection attempts
    if contains_special_chars(host):
        print_warning("Host contains special characters")
        return False
    
    self.target_host = host
    return True

# ❌ BAD: No validation
def set_target_host(host):
    self.target_host = host
```

### Secure Defaults

```python
# ✅ GOOD: Secure by default
DEFAULT_SSL_VERIFY = True
DEFAULT_TIMEOUT = 30
DEFAULT_MAX_RETRIES = 3

# ❌ BAD: Insecure defaults
DEFAULT_SSL_VERIFY = False  # Disables certificate verification
```

### Avoiding Common Vulnerabilities

1. **SQL Injection**: Use parameterized queries
2. **Command Injection**: Validate and sanitize input
3. **Path Traversal**: Validate file paths
4. **XSS**: Escape user input in web interfaces
5. **CSRF**: Use tokens for state-changing operations

```python
# ✅ GOOD: Parameterized query
cursor.execute("SELECT * FROM hosts WHERE ip = ?", (target_ip,))

# ❌ BAD: String concatenation
cursor.execute(f"SELECT * FROM hosts WHERE ip = '{target_ip}'")
```

### Secrets Management

```python
# ✅ GOOD: Don't hardcode secrets
api_key = os.environ.get('MSF_API_KEY')
if not api_key:
    print_error("API key not found in environment")
    return None

# ❌ BAD: Hardcoded secrets
api_key = "sk_live_abc123xyz789"  # Never do this!
```

## Code Review Process

### Before Submitting a PR

- [ ] Run linters (flake8, black, isort)
- [ ] Run tests and ensure they pass
- [ ] Add tests for new functionality
- [ ] Update documentation
- [ ] Review your own changes
- [ ] Address any TODO/FIXME comments in new code
- [ ] Ensure no secrets are committed
- [ ] Verify code follows style guidelines

### Self-Review Checklist

```bash
# Format code
python3 -m black lib/ modules/
python3 -m isort lib/ modules/

# Check style
python3 -m flake8 lib/ modules/

# Run tests
python3 -m pytest

# Check coverage
python3 -m pytest --cov=lib --cov=modules --cov-report=term-missing

# Review changes
git diff
```

### Code Review Guidelines

**For Reviewers:**
- Be constructive and respectful
- Focus on code, not the person
- Explain the "why" behind suggestions
- Approve if it improves the codebase

**For Authors:**
- Be open to feedback
- Ask questions if unclear
- Address all comments
- Thank reviewers for their time

## Tools and Automation

### Linting Tools

```bash
# Python linting
pip3 install flake8 black isort mypy

# Run Black (auto-format)
black lib/ modules/

# Run isort (sort imports)
isort lib/ modules/

# Run flake8 (style check)
flake8 lib/ modules/

# Run mypy (type checking)
mypy lib/ modules/
```

### Pre-commit Hooks

Create `.git/hooks/pre-commit`:

```bash
#!/bin/bash

# Format code
black lib/ modules/
isort lib/ modules/

# Run linters
flake8 lib/ modules/ || exit 1

# Run tests
python3 -m pytest -m "unit" || exit 1

echo "Pre-commit checks passed!"
```

### Configuration Files

#### `.flake8`
```ini
[flake8]
max-line-length = 120
ignore = E203, W503, E501
exclude = .git,__pycache__,build,dist
```

#### `pyproject.toml`
```toml
[tool.black]
line-length = 120
target-version = ['py311']

[tool.isort]
profile = "black"
line_length = 120
```

### Continuous Integration

All code changes are automatically checked by CI:

1. **Linting**: Ensures code follows style guidelines
2. **Testing**: Runs test suite
3. **Coverage**: Checks test coverage
4. **Security**: Scans for vulnerabilities

See `.github/workflows/` for CI configuration.

## File Size Guidelines

### Large Files in the Repository

Some files in the repository legitimately exceed 500 lines. This section documents these files and explains why they are acceptable:

#### Exploit Data Files
- `data/exploits/CVE-*/`: Binary exploit data files, media files (e.g., MPEG transport streams with `.ts` extension)
- These are **data files**, not source code, and should be excluded from code cleanliness checks

#### Transpilers and Code Generation Tools
- `tools/py2ruby_transpiler.py` (~977 lines): Ruby-to-Python transpiler
- `ruby2py/py2ruby/transpiler.py` (~977 lines): Core transpiler logic
- `tools/ast_transpiler/ast_translator.py` (~973 lines): AST translation engine
- These are complex code generation tools that inherently require comprehensive pattern matching

#### Test Suites
- `test/test_comprehensive_suite.py` (~664 lines): Comprehensive test suite
- `test/python_framework/test_http_client.py` (~575 lines): HTTP client tests
- `test/python_framework/test_exploit.py` (~566 lines): Exploit framework tests
- `test/python_framework/test_ssh_client.py` (~544 lines): SSH client tests
- Large test files are acceptable as they provide thorough coverage

#### Security Analysis Tools
- `lib/msf/util/llvm_instrumentation.py` (~716 lines): LLVM instrumentation for binary analysis
- `lib/rex/binary_analysis/fuzzer.py` (~512 lines): Fuzzing framework
- `lib/rex/binary_analysis/lldb_debugger.py` (~511 lines): LLDB debugger integration
- Security analysis tools require extensive functionality and configuration

#### Integration Modules
- `lib/msf/core/integrations/sliver.py` (~519 lines): Sliver C2 framework integration
- `scripts/meterpreter/winenum.py` (~521 lines): Windows enumeration script
- Complex integrations naturally require more code

### When Large Files Are a Problem

A file should be considered for refactoring if:
1. It has **high cyclomatic complexity** (many nested conditions)
2. It violates the **Single Responsibility Principle** (does multiple unrelated things)
3. It has **low test coverage** (under 70%)
4. It's difficult to understand or maintain

### File Size Guidelines by Type

- **Modules/Exploits**: Aim for under 500 lines
- **Test Files**: 500-1000 lines acceptable if well-organized
- **Tools/Utilities**: Consider splitting if over 1000 lines
- **Data Files**: No limit (these aren't code)

## Summary

Maintaining high code quality requires:

1. **Follow Style Guidelines**: Use Black, isort, and flake8
2. **Write Clear Code**: Code should be self-explanatory
3. **Document Appropriately**: Docstrings for public APIs
4. **Handle Errors Gracefully**: Specific exception handling
5. **Prioritize Security**: Validate input, use secure defaults
6. **Test Thoroughly**: Write tests for all new code
7. **Review Carefully**: Self-review before submitting
8. **Use Tools**: Automate quality checks
9. **Manage Technical Debt**: Track and address TODO/FIXME comments
10. **Continuous Improvement**: Regularly review and refine practices

Remember: Quality code is not just about working code—it's about code that's maintainable, secure, and a pleasure to work with.

## Additional Resources

- [PEP 8 - Style Guide for Python Code](https://www.python.org/dev/peps/pep-0008/)
- [Ruby Style Guide](https://github.com/bbatsov/ruby-style-guide)
- [Metasploit Contributing Guide](./CONTRIBUTING.md)
- [Metasploit Testing Guide](./TESTING.md)
- [OWASP Secure Coding Practices](https://owasp.org/www-project-secure-coding-practices-quick-reference-guide/)

Happy coding! 💻
