# Metasploit Framework Test Suite

## 🎯 Quick Start

```bash
# Install dependencies and setup
./scripts/test-quickstart.sh

# Run all tests
./run_comprehensive_tests.py

# Run specific test categories
./run_comprehensive_tests.py --categories unit security crypto
```

## 📚 Documentation

See [TESTING_COMPREHENSIVE_GUIDE.md](../TESTING_COMPREHENSIVE_GUIDE.md) for complete documentation.

## 🧪 Test Files

### New Comprehensive Test Suite

- **`test_comprehensive_suite.py`** - Complete unit tests for all components (600+ lines)
- **`test_property_based.py`** - Property-based tests using Hypothesis (420+ lines)
- **`test_fuzz.py`** - Fuzz tests with random/malformed data (500+ lines)
- **`test_integration_comprehensive.py`** - Integration tests (500+ lines)

### Legacy Tests

Contains files related to integration tests for things such as payload testing,
modules used in sanity testing, as well as tests that can be exercised using
https://github.com/rapid7/geppetto.

## 🚀 Running Tests

### Using the Test Runner

```bash
# All tests
./run_comprehensive_tests.py --verbose

# Quick tests only (skip slow tests)
./run_comprehensive_tests.py --quick

# With coverage
./run_comprehensive_tests.py --coverage

# Specific categories
./run_comprehensive_tests.py --categories unit
./run_comprehensive_tests.py --categories security crypto
./run_comprehensive_tests.py --categories integration network
```

### Using Make

```bash
# View all targets
make -f Makefile.testing help

# Common commands
make -f Makefile.testing test
make -f Makefile.testing test-unit
make -f Makefile.testing test-coverage
make -f Makefile.testing test-quick
```

### Using pytest Directly

```bash
# All tests
pytest test/ -v

# Specific file
pytest test/test_comprehensive_suite.py -v

# By marker
pytest -m unit
pytest -m security
pytest -m "unit and not slow"

# Specific test
pytest test/test_comprehensive_suite.py::TestFrameworkCore::test_framework_imports -v
```

## 📊 Test Categories

- **Unit Tests** (`-m unit`) - Individual component tests
- **Property-Based Tests** - Hypothesis-generated test cases
- **Fuzz Tests** - Random/malformed input tests
- **Integration Tests** (`-m integration`) - Component interaction tests
- **Security Tests** (`-m security`) - Security-critical code tests
- **Crypto Tests** (`-m crypto`) - Cryptographic function tests
- **Performance Tests** (`-m performance`) - Performance benchmarks
- **Network Tests** (`-m network`) - Network protocol tests

## 🎨 Test Markers

```python
@pytest.mark.unit           # Unit test
@pytest.mark.integration    # Integration test
@pytest.mark.security       # Security test
@pytest.mark.crypto         # Cryptographic test
@pytest.mark.performance    # Performance test
@pytest.mark.slow           # Slow test (skipped in quick mode)
@pytest.mark.network        # Requires network
```

## 📈 Coverage

```bash
# Generate coverage report
make -f Makefile.testing test-coverage

# View HTML report
open htmlcov/index.html

# Show terminal report
make -f Makefile.testing coverage-report
```

## 🔧 Pre-commit Hooks

```bash
# Install pre-commit hooks
make -f Makefile.testing setup-hooks

# Hooks will run:
# - Python syntax check
# - Flake8 linting
# - Quick unit tests
# - Debugger statement check
```

## 🏆 Test Philosophy

**TEST ALL THE THINGS!** 🚀

- Comprehensive coverage
- Automated execution
- Fast feedback
- Security-focused
- Property-based testing
- Fuzz testing
- Integration testing
- Continuous testing

For complete documentation, see [TESTING_COMPREHENSIVE_GUIDE.md](../TESTING_COMPREHENSIVE_GUIDE.md)