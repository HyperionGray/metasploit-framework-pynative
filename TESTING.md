# Testing Guide for Metasploit Framework

This document provides comprehensive guidance on testing the Metasploit Framework, including running tests, writing new tests, and understanding test coverage.

## Table of Contents

- [Overview](#overview)
- [Test Infrastructure](#test-infrastructure)
- [Running Tests](#running-tests)
- [Writing Tests](#writing-tests)
- [Test Coverage](#test-coverage)
- [Testing Best Practices](#testing-best-practices)
- [Continuous Integration](#continuous-integration)

## Overview

The Metasploit Framework uses multiple testing frameworks to ensure code quality and reliability:

- **Pytest**: Primary testing framework for Python code
- **Unittest**: Standard Python unit testing framework
- **RSpec**: Ruby testing framework for legacy code
- **Integration Tests**: End-to-end testing for complete workflows

### Test Structure

```
test/                    # Python test files
├── framework/          # Core framework tests
├── network/            # Network-related tests
├── crypto/             # Cryptographic function tests
├── binary_analysis/    # Binary analysis tool tests
└── functional/         # Functional/integration tests

spec/                   # Ruby spec files (legacy)
├── acceptance/         # Acceptance tests
├── api/                # API tests
└── models/             # Model tests
```

## Test Infrastructure

### Python Testing Setup

Install the required testing dependencies:

```bash
# Install all requirements
pip3 install -r requirements.txt

# Or install test-specific requirements
pip3 install pytest pytest-cov pytest-timeout pytest-mock
```

### Configuration

Test configuration is managed in `pyproject.toml`:

```toml
[tool.pytest.ini_options]
testpaths = ["test", "spec"]
python_files = ["test_*.py", "*_test.py", "*_spec.py"]
```

## Running Tests

### Run All Tests

```bash
# Run all Python tests
python3 -m pytest

# Run all Ruby specs
bundle exec rspec
```

### Run Specific Test Categories

Use pytest markers to run specific test categories:

```bash
# Unit tests only
python3 -m pytest -m unit

# Integration tests
python3 -m pytest -m integration

# Security tests
python3 -m pytest -m security

# Network tests (requires network access)
python3 -m pytest -m network

# Exclude slow tests
python3 -m pytest -m "not slow"
```

### Available Test Markers

- `unit`: Unit tests for individual components
- `integration`: Integration tests between components
- `functional`: Functional tests for complete workflows
- `security`: Security-focused tests
- `performance`: Performance and benchmark tests
- `network`: Tests requiring network access
- `slow`: Tests that take a long time to run
- `exploit`: Tests for exploit modules
- `auxiliary`: Tests for auxiliary modules
- `payload`: Tests for payload modules
- `encoder`: Tests for encoder modules
- `crypto`: Tests for cryptographic functions
- `http`: Tests for HTTP client functionality
- `rex`: Tests for Rex library components
- `msf`: Tests for MSF core components

### Run Tests for Specific Files

```bash
# Test a specific file
python3 -m pytest test/network/test_http_client.py

# Test a specific function
python3 -m pytest test/network/test_http_client.py::test_basic_get

# Run tests with verbose output
python3 -m pytest -v test/framework/

# Run tests with detailed output
python3 -m pytest -vv test/crypto/
```

### Run Tests with Coverage

```bash
# Run with coverage report
python3 -m pytest --cov=lib --cov=modules --cov-report=html

# View coverage report
open htmlcov/index.html  # macOS
xdg-open htmlcov/index.html  # Linux
```

## Writing Tests

### Test File Structure

Create test files following these naming conventions:

- `test_<module_name>.py` - For testing a specific module
- `<feature>_test.py` - Alternative naming convention
- `<feature>_spec.py` - For behavior-driven tests

### Basic Test Example

```python
import pytest
from lib.msf.core import Framework

class TestFramework:
    """Test Framework core functionality."""
    
    def test_framework_initialization(self):
        """Test that framework initializes correctly."""
        framework = Framework()
        assert framework is not None
        assert framework.version is not None
    
    def test_module_loading(self):
        """Test that modules can be loaded."""
        framework = Framework()
        module = framework.modules.create('exploit/multi/handler')
        assert module is not None
```

### Using Fixtures

```python
import pytest

@pytest.fixture
def framework():
    """Provide a Framework instance for tests."""
    from lib.msf.core import Framework
    return Framework()

def test_with_fixture(framework):
    """Test using a fixture."""
    assert framework.version is not None
```

### Marking Tests

```python
import pytest

@pytest.mark.unit
def test_unit_example():
    """A unit test example."""
    pass

@pytest.mark.integration
@pytest.mark.network
def test_network_integration():
    """An integration test requiring network."""
    pass

@pytest.mark.slow
@pytest.mark.security
def test_security_scan():
    """A slow security test."""
    pass
```

### Parameterized Tests

```python
import pytest

@pytest.mark.parametrize("input,expected", [
    ("test", 4),
    ("hello", 5),
    ("", 0),
])
def test_string_length(input, expected):
    """Test string length calculation."""
    assert len(input) == expected
```

### Testing Exceptions

```python
import pytest

def test_exception_handling():
    """Test that exceptions are raised correctly."""
    with pytest.raises(ValueError, match="Invalid input"):
        raise ValueError("Invalid input")
```

### Mocking and Patching

```python
from unittest.mock import patch, MagicMock

@patch('lib.msf.core.network.http_client.requests.get')
def test_http_client_mock(mock_get):
    """Test HTTP client with mocked requests."""
    mock_response = MagicMock()
    mock_response.status_code = 200
    mock_response.text = "Success"
    mock_get.return_value = mock_response
    
    # Your test code here
    from lib.msf.core.network.http_client import HttpClient
    client = HttpClient()
    response = client.get("http://example.com")
    assert response.status_code == 200
```

## Test Coverage

### Viewing Coverage Reports

```bash
# Generate coverage report
python3 -m pytest --cov=lib --cov=modules --cov-report=term-missing

# Generate HTML coverage report
python3 -m pytest --cov=lib --cov=modules --cov-report=html

# Generate XML coverage report (for CI)
python3 -m pytest --cov=lib --cov=modules --cov-report=xml
```

### Coverage Goals

- **Minimum Coverage**: 80% (enforced by CI)
- **Critical Components**: Aim for 90%+ coverage
- **New Code**: Should include tests achieving 80%+ coverage

### Identifying Untested Code

```bash
# Show lines missing coverage
python3 -m pytest --cov=lib --cov-report=term-missing

# Generate coverage report and identify gaps
python3 -m pytest --cov=lib --cov-report=html
open htmlcov/index.html
```

## Testing Best Practices

### 1. Write Clear, Descriptive Tests

```python
# Good
def test_framework_loads_exploit_module_successfully():
    """Test that the framework can load an exploit module."""
    pass

# Avoid
def test1():
    """Test."""
    pass
```

### 2. Test One Thing at a Time

```python
# Good - Single assertion
def test_module_name():
    module = load_module('exploit/multi/handler')
    assert module.name == "multi/handler"

def test_module_type():
    module = load_module('exploit/multi/handler')
    assert module.type == "exploit"

# Avoid - Multiple unrelated assertions
def test_module():
    module = load_module('exploit/multi/handler')
    assert module.name == "multi/handler"
    assert module.type == "exploit"
    assert module.description is not None
    # ... many more assertions
```

### 3. Use Meaningful Test Data

```python
# Good
def test_payload_generation_with_reverse_tcp():
    payload = generate_payload('windows/meterpreter/reverse_tcp')
    assert payload.type == 'reverse_tcp'

# Avoid
def test_payload():
    p = gen('x')
    assert p.t == 'r'
```

### 4. Clean Up After Tests

```python
import pytest
import tempfile
import os

@pytest.fixture
def temp_file():
    """Create a temporary file and clean up after test."""
    fd, path = tempfile.mkstemp()
    os.close(fd)
    yield path
    if os.path.exists(path):
        os.remove(path)

def test_with_temp_file(temp_file):
    """Test using a temporary file."""
    with open(temp_file, 'w') as f:
        f.write("test data")
    # Test logic here
    # File is automatically cleaned up after test
```

### 5. Test Edge Cases and Error Conditions

```python
def test_divide_by_zero():
    """Test division by zero raises appropriate error."""
    with pytest.raises(ZeroDivisionError):
        result = 10 / 0

def test_empty_input():
    """Test handling of empty input."""
    result = process_data([])
    assert result == []

def test_none_input():
    """Test handling of None input."""
    with pytest.raises(ValueError, match="Input cannot be None"):
        process_data(None)
```

### 6. Keep Tests Fast

- Mock external services and APIs
- Use in-memory databases for testing
- Avoid unnecessary sleeps or waits
- Mark slow tests with `@pytest.mark.slow`

### 7. Make Tests Independent

```python
# Good - Tests are independent
def test_user_creation():
    user = create_user("test@example.com")
    assert user.email == "test@example.com"

def test_user_deletion():
    user = create_user("test2@example.com")
    delete_user(user)
    assert get_user(user.id) is None

# Avoid - Tests depend on each other
def test_step1():
    global user
    user = create_user("test@example.com")

def test_step2():
    # This test depends on test_step1 running first
    assert user.email == "test@example.com"
```

## Continuous Integration

### GitHub Actions

Tests are automatically run on:
- Pull requests
- Pushes to master
- Nightly builds

### CI Test Commands

```bash
# Linting
python3 -m flake8 lib/ modules/
python3 -m black --check lib/ modules/

# Unit tests
python3 -m pytest -m unit

# Integration tests
python3 -m pytest -m integration

# All tests with coverage
python3 -m pytest --cov=lib --cov=modules --cov-report=xml
```

### CI Configuration

See `.github/workflows/test.yml` for the complete CI configuration.

## Troubleshooting

### Common Issues

#### Tests Not Found

```bash
# Make sure you're in the project root
cd /path/to/metasploit-framework-pynative

# Check test discovery
python3 -m pytest --collect-only
```

#### Import Errors

```bash
# Install dependencies
pip3 install -r requirements.txt

# Ensure project is in PYTHONPATH
export PYTHONPATH="${PYTHONPATH}:$(pwd)"
```

#### Timeout Issues

```bash
# Increase timeout for slow tests
python3 -m pytest --timeout=600

# Or skip slow tests
python3 -m pytest -m "not slow"
```

### Getting Help

- **GitHub Discussions**: [Ask the community](https://github.com/rapid7/metasploit-framework/discussions)
- **Slack**: [Join Metasploit Slack](https://join.slack.com/t/metasploit/shared_invite/...)
- **Documentation**: [Metasploit Docs](https://docs.metasploit.com/)

## Additional Resources

- [Pytest Documentation](https://docs.pytest.org/)
- [Python unittest Documentation](https://docs.python.org/3/library/unittest.html)
- [RSpec Documentation](https://rspec.info/)
- [Metasploit Module Documentation](https://docs.metasploit.com/docs/development/developing-modules/)
- [Contributing Guide](./CONTRIBUTING.md)

## Summary

Testing is a critical part of maintaining the Metasploit Framework. By following these guidelines and best practices, you can help ensure that:

1. New features work as expected
2. Bug fixes don't introduce regressions
3. The codebase remains maintainable
4. Security vulnerabilities are caught early
5. Code quality remains high

Remember:
- ✅ Write tests for all new code
- ✅ Run tests before submitting PRs
- ✅ Aim for meaningful test coverage
- ✅ Test edge cases and error conditions
- ✅ Keep tests fast and independent
- ✅ Use descriptive test names
- ✅ Mark tests appropriately with pytest markers

Happy testing! 🧪
