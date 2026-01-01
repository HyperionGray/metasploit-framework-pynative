# Security Best Practices

## Overview

This document outlines security best practices for contributors to the Metasploit Framework Python-Native fork.

## Dangerous Code Patterns to Avoid

### 1. Dynamic Code Execution

**NEVER use these functions with untrusted input:**

```python
# DANGEROUS - Do not use
eval(user_input)
exec(user_input)
compile(user_input, '<string>', 'exec')
__import__(user_input)
```

**Why?** These functions execute arbitrary code and can lead to Remote Code Execution (RCE) vulnerabilities.

**Safe Alternatives:**
- Use `ast.literal_eval()` for parsing literals safely
- Use proper parsing libraries (json, yaml with SafeLoader, etc.)
- Use dictionaries for mapping instead of dynamic imports
- Validate and sanitize all inputs

### 2. Command Injection

**Avoid shell=True in subprocess calls:**

```python
# DANGEROUS
subprocess.call(f"ls {user_input}", shell=True)

# SAFE
subprocess.call(["ls", user_input])
```

### 3. SQL Injection

**Use parameterized queries:**

```python
# DANGEROUS
cursor.execute(f"SELECT * FROM users WHERE id = {user_id}")

# SAFE
cursor.execute("SELECT * FROM users WHERE id = ?", (user_id,))
```

### 4. Path Traversal

**Validate file paths:**

```python
import os
from pathlib import Path

# Validate that path is within expected directory
base_dir = Path("/safe/directory")
user_path = Path(user_input).resolve()

if not str(user_path).startswith(str(base_dir)):
    raise ValueError("Invalid path")
```

### 5. Deserialization of Untrusted Data

**Avoid pickle with untrusted data:**

```python
# DANGEROUS
import pickle
data = pickle.loads(untrusted_data)

# SAFER - use json or other safe formats
import json
data = json.loads(untrusted_data)
```

## Legacy Code in This Repository

### Deprecated Directories

The following directories contain legacy/deprecated code that may include unsafe patterns. These are kept for historical reference only:

- `bak/` - Backup and deprecated scripts
- `ruby2py/deprecated/` - Deprecated Ruby-to-Python conversion scripts

**Note:** Some files in these directories use `exec()` and other potentially unsafe patterns. These scripts:
- Are NOT part of the active codebase
- Should NOT be used in production
- Are kept for reference purposes only
- May contain security vulnerabilities

### Safe Usage Context

In penetration testing tools like Metasploit, some modules intentionally demonstrate or exploit vulnerabilities. This is acceptable when:

1. The code is clearly documented as an exploit demonstration
2. It's used only in controlled testing environments
3. It's not executed on production systems
4. Users have explicit authorization to test target systems

## Module Development Guidelines

### Input Validation

```python
def validate_input(value, pattern):
    """Validate user input against expected pattern"""
    import re
    if not re.match(pattern, value):
        raise ValueError(f"Invalid input: {value}")
    return value
```

### Output Encoding

```python
import html

def safe_output(data):
    """Safely encode output to prevent XSS"""
    return html.escape(str(data))
```

### Secure Randomness

```python
# WRONG - not cryptographically secure
import random
token = random.randint(1000, 9999)

# CORRECT - cryptographically secure
import secrets
token = secrets.token_hex(16)
```

## Security Review Checklist

Before submitting code, verify:

- [ ] No use of `eval()` or `exec()` with external input
- [ ] No `shell=True` in subprocess calls
- [ ] All SQL queries use parameterized statements
- [ ] File paths are validated
- [ ] No hardcoded secrets or credentials
- [ ] Cryptographic operations use secure libraries (cryptography, not pycrypto)
- [ ] Random number generation uses `secrets` module for security-sensitive operations
- [ ] All external inputs are validated and sanitized
- [ ] Error messages don't leak sensitive information

## Testing Security

### Run Security Linters

```bash
# Check for common security issues
bandit -r lib/ modules/ -f json -o security-report.json

# Check for hardcoded secrets
gitleaks detect --source . -v
```

### Manual Security Review

1. Review all code that handles external input
2. Check for proper error handling (no information leakage)
3. Verify authentication and authorization logic
4. Test with malicious inputs
5. Review cryptographic implementations

## Reporting Security Issues

**DO NOT report security vulnerabilities in public issues.**

Follow the process in [SECURITY.md](../SECURITY.md):

1. Email: [security@rapid7.com](mailto:security@rapid7.com)
2. Include detailed reproduction steps
3. Allow time for coordinated disclosure

## Resources

- [OWASP Top 10](https://owasp.org/www-project-top-ten/)
- [Python Security Best Practices](https://python.readthedocs.io/en/stable/library/security_warnings.html)
- [Bandit Security Linter](https://bandit.readthedocs.io/)
- [OWASP Python Security Project](https://owasp.org/www-project-python-security/)

## Updates

This document should be reviewed and updated regularly as new security patterns emerge and Python evolves.

Last updated: 2025-12-28
