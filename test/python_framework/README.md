# Python Framework Testing Guide

This document describes the testing infrastructure for the Python-native Metasploit Framework components.

## Overview

The Python framework has comprehensive test coverage with **141 total tests (140 passing, 1 skipped)** covering all major components.

## Running Tests

### Run All Tests
```bash
python3 -m pytest test/python_framework/ -v
```

### Run Specific Test File
```bash
python3 -m pytest test/python_framework/test_exploit.py -v
python3 -m pytest test/python_framework/test_http_client.py -v
python3 -m pytest test/python_framework/test_ssh_client.py -v
python3 -m pytest test/python_framework/test_route.py -v
```

### Run Tests with Coverage
```bash
python3 -m pytest test/python_framework/ --cov=python_framework --cov-report=html
```

## Test Structure

All tests follow the `unittest.TestCase` pattern for consistency with existing Metasploit tests.

### Test Files

| File | Tests | Component | Coverage |
|------|-------|-----------|----------|
| `test_exploit.py` | 37 | Core exploit classes | Full |
| `test_http_client.py` | 44 | HTTP client helper | Full |
| `test_ssh_client.py` | 37 | SSH client helper | Full |
| `test_route.py` | 22 | Network routing | Full |

### Test Organization

Each test file is organized into test classes:

```python
class TestClassName(unittest.TestCase):
    """Test specific component or feature"""
    
    def setUp(self):
        """Set up test fixtures"""
        pass
    
    def test_specific_functionality(self):
        """Test description"""
        # Test implementation
        pass
```

## Test Patterns

### 1. Initialization Tests
Test that components initialize correctly with default and custom parameters.

```python
def test_initialization_defaults(self):
    """Test default initialization"""
    client = HttpClient()
    self.assertEqual(client.timeout, 10)
    self.assertFalse(client.verbose)
```

### 2. Mocking External Dependencies
Use `unittest.mock` to isolate tests from external dependencies.

```python
@patch("paramiko.SSHClient")
def test_connect_with_password(self, mock_ssh_class):
    """Test SSH connection"""
    mock_ssh_instance = MagicMock()
    mock_ssh_class.return_value = mock_ssh_instance
    
    client = SSHClient(hostname="example.com")
    result = client.connect()
    
    self.assertTrue(result)
```

### 3. Error Handling Tests
Verify proper exception handling and error conditions.

```python
def test_execute_command_not_connected(self):
    """Test error when not connected"""
    client = SSHClient(hostname="example.com")
    
    with self.assertRaises(RuntimeError):
        client.execute_command("ls -la")
```

### 4. Edge Case Tests
Test boundary conditions and unusual inputs.

```python
def test_route_with_zero_address(self):
    """Test route with 0.0.0.0 (default route)"""
    route = Route('0.0.0.0', '0.0.0.0', '192.168.1.1')
    self.assertEqual(route.subnet, '0.0.0.0')
```

## Adding New Tests

### 1. Create Test File
Follow the naming convention: `test_<component_name>.py`

### 2. Import Dependencies
```python
import unittest
from unittest.mock import Mock, MagicMock, patch

from python_framework.component import Component
```

### 3. Create Test Class
```python
class TestComponent(unittest.TestCase):
    """Test Component class"""
    
    def test_feature(self):
        """Test specific feature"""
        component = Component()
        # Test assertions
```

### 4. Run Tests
```bash
python3 -m pytest test/python_framework/test_component.py -v
```

## Test Coverage by Component

### exploit.py (37 tests)
- Enums (ExploitRank, TargetArch, Platform, PayloadType)
- Dataclasses (ExploitTarget, ExploitOption, ExploitInfo, ExploitResult)
- Exploit base class (options, targets, execution)
- RemoteExploit and LocalExploit classes
- Workflows and error handling

### http_client.py (44 tests)
- HttpClient initialization and configuration
- HTTP methods (GET, POST, PUT, DELETE, HEAD, OPTIONS)
- URL building and headers
- Cookies and parameters
- Timeout and redirect control
- HttpExploitMixin integration

### ssh_client.py (37 tests)
- SSHClient initialization and connection
- Command execution and output capture
- File transfer (upload/download)
- Interactive shell operations
- SSH key generation and management
- SSHExploitMixin integration

### route.py (22 tests)
- Route initialization (IPv4/IPv6, string/bytes)
- String representations
- Equality and hashing
- Dictionary serialization
- Edge cases

## Dependencies

Required packages for testing:
```bash
pip3 install pytest pytest-mock paramiko
```

## Known Issues

1. **SSH Key Test Skipped**: One test in `test_ssh_client.py` is skipped due to DSAKey being deprecated in paramiko 4.0. The implementation needs to be updated to remove DSA key support.

## Best Practices

1. **Mock External Services**: Always mock network calls, SSH connections, database connections
2. **Test One Thing**: Each test should test one specific behavior
3. **Clear Test Names**: Use descriptive names that explain what is being tested
4. **Setup/Teardown**: Use setUp() and tearDown() for common initialization
5. **Test Errors**: Include tests for error conditions and exceptions
6. **Edge Cases**: Don't forget boundary conditions and unusual inputs
7. **Documentation**: Add docstrings to test methods explaining what they test

## Continuous Integration

Tests should be run automatically in CI/CD pipelines:

```yaml
# .github/workflows/test.yml
- name: Run Python Framework Tests
  run: python3 -m pytest test/python_framework/ -v
```

## Troubleshooting

### Import Errors
Ensure you're running tests from the repository root:
```bash
cd /path/to/metasploit-framework-pynative
python3 -m pytest test/python_framework/
```

### Mock Not Working
Check that you're patching the right location:
```python
# Patch where it's used, not where it's defined
@patch("python_framework.helpers.http_client.requests.Session.request")
```

### Test Discovery Issues
Ensure test files and functions follow naming conventions:
- Files: `test_*.py` or `*_test.py`
- Classes: `Test*`
- Methods: `test_*`

## Resources

- [pytest Documentation](https://docs.pytest.org/)
- [unittest Documentation](https://docs.python.org/3/library/unittest.html)
- [unittest.mock Guide](https://docs.python.org/3/library/unittest.mock.html)
- [Metasploit Framework Testing Guide](https://docs.metasploit.com/docs/development/developing-modules/module-testing.html)
