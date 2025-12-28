# Test Coverage Guide

## Overview

This guide documents the testing approach, coverage strategy, and best practices for the Metasploit Framework Python-Native fork.

## Test Infrastructure

### Pytest Configuration

Testing is configured in `pyproject.toml` with comprehensive settings:

```toml
[tool.pytest.ini_options]
testpaths = ["test", "spec"]
python_files = ["test_*.py", "*_test.py", "*_spec.py"]
python_classes = ["Test*", "Describe*"]
python_functions = ["test_*", "it_*", "should_*"]
```

### Coverage Configuration

Coverage tracking is enabled with the following settings:

```toml
[tool.coverage.run]
source = ["lib", "modules", "tools"]
omit = [
    "*/tests/*",
    "*/test_*",
    "*/__pycache__/*",
    "*/migrations/*",
    "*/venv/*",
    "*/virtualenv/*"
]
```

**Target**: 80% code coverage minimum

## Running Tests

### Run All Tests

```bash
pytest
```

### Run Specific Test Categories

```bash
# Unit tests only
pytest -m unit

# Integration tests
pytest -m integration

# Security tests
pytest -m security

# Slow tests (explicitly)
pytest -m slow

# Skip slow tests
pytest -m "not slow"
```

### Run Tests for Specific Components

```bash
# Test a specific module
pytest test/lib/rex/

# Test a specific file
pytest test/lib/rex/test_socket.py

# Test a specific function
pytest test/lib/rex/test_socket.py::test_socket_creation
```

### Generate Coverage Reports

```bash
# Terminal report
pytest --cov=lib --cov=modules --cov-report=term-missing

# HTML report
pytest --cov=lib --cov=modules --cov-report=html

# Both
pytest --cov=lib --cov=modules --cov-report=term-missing --cov-report=html
```

## Test Organization

### Directory Structure

```
test/                      # Python tests (new style)
├── lib/                   # Tests for lib/ components
│   ├── rex/              # Rex library tests
│   ├── msf/              # MSF core tests
│   └── ...
├── modules/              # Module tests
│   ├── exploits/
│   ├── auxiliary/
│   └── payloads/
└── integration/          # Integration tests

spec/                     # RSpec tests (legacy, being migrated)
├── lib/
└── modules/
```

### Current Test Coverage

As of December 2024:
- **54 Python test files** across test directories
- **13+ test directories** covering different components
- **Multiple test types**: unit, integration, functional, security

## Test Markers

Tests are categorized using pytest markers:

| Marker | Description | Usage |
|--------|-------------|-------|
| `unit` | Unit tests for individual components | Fast, isolated tests |
| `integration` | Integration tests between components | Tests component interaction |
| `functional` | End-to-end workflow tests | Complete feature tests |
| `security` | Security-focused tests | Crypto, exploit validation |
| `performance` | Performance benchmarks | Timed tests |
| `slow` | Long-running tests | May take minutes |
| `network` | Tests requiring network | External connectivity needed |
| `binary_analysis` | Binary analysis tool tests | Requires Radare2/LLDB |
| `exploit` | Exploit module tests | Module functionality |
| `payload` | Payload generation tests | Payload handling |
| `crypto` | Cryptographic function tests | Encryption/hashing |
| `framework` | Core framework tests | Framework core |

### Using Markers

```python
import pytest

@pytest.mark.unit
def test_simple_function():
    assert True

@pytest.mark.integration
@pytest.mark.network
def test_network_integration():
    # Test that requires network
    pass

@pytest.mark.slow
@pytest.mark.performance
def test_heavy_operation():
    # Long-running test
    pass
```

## Writing Tests

### Test Structure

```python
import pytest
from lib.msf.core.module import Module

class TestModule:
    """Tests for MSF Module class"""
    
    def setup_method(self):
        """Setup before each test method"""
        self.module = Module()
    
    def teardown_method(self):
        """Cleanup after each test method"""
        pass
    
    @pytest.mark.unit
    def test_module_initialization(self):
        """Test module initializes correctly"""
        assert self.module is not None
    
    @pytest.mark.unit
    def test_module_info(self):
        """Test module info returns expected data"""
        info = self.module.info
        assert 'name' in info
        assert 'description' in info
```

### Test Fixtures

```python
import pytest

@pytest.fixture
def sample_module():
    """Fixture providing a sample module"""
    module = Module()
    module.load()
    yield module
    module.cleanup()

@pytest.mark.unit
def test_with_fixture(sample_module):
    """Test using fixture"""
    assert sample_module.loaded is True
```

### Parameterized Tests

```python
import pytest

@pytest.mark.parametrize("input,expected", [
    ("hello", "HELLO"),
    ("world", "WORLD"),
    ("test", "TEST"),
])
def test_uppercase(input, expected):
    """Test uppercase conversion"""
    assert input.upper() == expected
```

## Test Coverage Goals

### Priority Areas

1. **Core Framework** (lib/msf/core/)
   - Target: 90%+ coverage
   - Critical: authentication, session management, module loading

2. **Rex Library** (lib/rex/)
   - Target: 85%+ coverage
   - Critical: socket handling, protocol implementations, encoders

3. **Exploits** (modules/exploits/)
   - Target: 70%+ coverage
   - Focus: initialization, option handling, exploit logic

4. **Payloads** (modules/payloads/)
   - Target: 80%+ coverage
   - Critical: payload generation, encoding, stagers

5. **Auxiliary Modules** (modules/auxiliary/)
   - Target: 75%+ coverage
   - Focus: scanner functionality, data collection

### Coverage by Component

To check current coverage:

```bash
# Overall coverage
pytest --cov=lib --cov=modules --cov-report=term-missing

# Coverage for specific component
pytest --cov=lib/msf/core --cov-report=term-missing test/lib/msf/core/

# Generate detailed HTML report
pytest --cov=lib --cov=modules --cov-report=html
# View htmlcov/index.html
```

## Continuous Integration

Tests run automatically on:
- Pull requests
- Commits to main branches
- Scheduled nightly runs

### CI Test Matrix

- Python 3.11
- Multiple OS: Linux, macOS, Windows
- Fast tests on PR, full suite on merge

## Testing Best Practices

### DO

✅ Write tests for all new code
✅ Test edge cases and error conditions
✅ Use descriptive test names
✅ Keep tests focused and isolated
✅ Use appropriate markers
✅ Mock external dependencies
✅ Test both success and failure paths
✅ Document complex test setups

### DON'T

❌ Write tests that depend on external services (unless marked `@pytest.mark.network`)
❌ Write tests that modify global state without cleanup
❌ Write tests that are flaky or non-deterministic
❌ Skip writing tests for "simple" code
❌ Test implementation details instead of behavior
❌ Write tests that take unnecessarily long to run

## Security Testing

### Security Test Categories

1. **Input Validation**
   ```python
   @pytest.mark.security
   def test_sql_injection_prevention():
       # Test SQL injection is prevented
       pass
   ```

2. **Authentication/Authorization**
   ```python
   @pytest.mark.security
   def test_unauthorized_access_denied():
       # Test access control
       pass
   ```

3. **Cryptography**
   ```python
   @pytest.mark.security
   @pytest.mark.crypto
   def test_encryption_strength():
       # Test crypto implementation
       pass
   ```

4. **Code Execution Prevention**
   ```python
   @pytest.mark.security
   def test_no_code_injection():
       # Test code injection prevention
       pass
   ```

## Legacy Tests (RSpec)

The `spec/` directory contains legacy RSpec tests from the original Ruby codebase. These are being gradually migrated to Python/pytest.

### Running RSpec Tests

```bash
bundle exec rspec spec/
```

### Migration Status

Active migration of RSpec tests to pytest is ongoing. Priority:
1. Core framework tests
2. Critical module tests
3. Helper/utility tests

## Resources

- [Pytest Documentation](https://docs.pytest.org/)
- [Coverage.py Documentation](https://coverage.readthedocs.io/)
- [Python Testing Best Practices](https://docs.python-guide.org/writing/tests/)
- Repository: [TESTING.md](../TESTING.md)
- Repository: [TESTING_COMPREHENSIVE_GUIDE.md](../TESTING_COMPREHENSIVE_GUIDE.md)

## Contributing Tests

When contributing new tests:

1. Follow existing test structure
2. Use appropriate markers
3. Ensure tests are isolated
4. Add docstrings to test classes and methods
5. Run tests locally before submitting PR
6. Aim to maintain or improve coverage

## Questions?

For questions about testing:
- Check [TESTING.md](../TESTING.md) for comprehensive testing guide
- Review existing tests for examples
- Ask in GitHub Discussions
- Join the Metasploit Slack

---

Last updated: 2025-12-28
