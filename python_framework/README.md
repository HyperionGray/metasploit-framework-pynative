# Python-Native Metasploit Framework

This directory contains the Python implementation of the Metasploit Framework, focusing on post-2020 content and new development.

## Structure

- `core/` - Core framework classes and functionality
- `exploits/` - Python exploit modules
- `auxiliary/` - Python auxiliary modules
- `helpers/` - Helper functions and utilities for exploit development
- `protocols/` - Protocol handlers (HTTP, SSH, SMB, etc.)
- `payloads/` - Payload generation and handling

## Key Features

- **Modern Python**: Uses Python 3.8+ features and best practices
- **Type Hints**: Full type annotation for better IDE support and code quality
- **Async Support**: Asynchronous operations for better performance
- **Modular Design**: Clean separation of concerns and easy extensibility
- **Framework Integration**: Seamless integration with existing Metasploit infrastructure

## Usage

```python
from python_framework.core.exploit import Exploit
from python_framework.helpers.http import HttpClient

class MyExploit(Exploit):
    def __init__(self):
        super().__init__(
            name="My Exploit",
            description="Description of the exploit",
            author="Author Name",
            references=["CVE-2024-XXXXX"]
        )
    
    def check(self):
        # Vulnerability check logic
        pass
    
    def exploit(self):
        # Exploitation logic
        pass
```

## Migration from Ruby

Ruby modules are automatically converted to Python using established patterns:
- Class inheritance structure maintained
- Method signatures preserved where possible
- Ruby-specific constructs translated to Python equivalents
- Framework integration points updated for Python

## Development Guidelines

1. Use type hints for all function signatures
2. Follow PEP 8 style guidelines
3. Include comprehensive docstrings
4. Write unit tests for all new functionality
5. Use async/await for I/O operations where appropriate