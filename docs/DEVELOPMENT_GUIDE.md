# Developer Quick Start Guide

Welcome to Metasploit Framework development! This guide will help you get started quickly with contributing to the project.

## 📚 Essential Documentation

Before diving in, familiarize yourself with these key documents:

- **[CONTRIBUTING.md](../CONTRIBUTING.md)** - Complete contribution guidelines
- **[TESTING.md](../TESTING.md)** - Comprehensive testing guide
- **[CODE_QUALITY.md](../CODE_QUALITY.md)** - Code quality standards and best practices
- **[README.md](../README.md)** - Project overview and installation
- **[.github/SECURITY.md](../.github/SECURITY.md)** - Security vulnerability reporting

## 🚀 Quick Start

### 1. Set Up Your Development Environment

```bash
# Clone the repository
git clone https://github.com/P4X-ng/metasploit-framework-pynative.git
cd metasploit-framework-pynative

# Create a feature branch
git checkout -b feature/your-feature-name

# Install Python dependencies
pip3 install -r requirements.txt

# Install Ruby dependencies (for legacy code)
bundle install
```

### 2. Make Your Changes

Follow these guidelines:

- ✅ Write clear, descriptive commit messages
- ✅ Keep changes focused and minimal
- ✅ Add tests for new functionality
- ✅ Update documentation as needed
- ✅ Follow coding standards (see CODE_QUALITY.md)

### 3. Test Your Changes

```bash
# Format your code
python3 -m black lib/ modules/
python3 -m isort lib/ modules/

# Check code style
python3 -m flake8 lib/ modules/

# Run tests
python3 -m pytest

# Check test coverage
python3 -m pytest --cov=lib --cov=modules --cov-report=term-missing

# Analyze what needs tests
python3 scripts/check_test_coverage.py --directory lib
```

### 4. Submit Your Pull Request

```bash
# Commit your changes
git add .
git commit -m "Brief description of changes"

# Push to your fork
git push origin feature/your-feature-name

# Create a Pull Request on GitHub
# Fill out the PR template completely
```

## 🧪 Testing Workflow

### Running Tests

```bash
# All tests
python3 -m pytest

# Specific test file
python3 -m pytest test/network/test_http_client.py

# Tests by category
python3 -m pytest -m unit          # Unit tests only
python3 -m pytest -m integration   # Integration tests
python3 -m pytest -m security      # Security tests
python3 -m pytest -m "not slow"    # Skip slow tests

# With coverage
python3 -m pytest --cov=lib --cov-report=html
open htmlcov/index.html  # View coverage report
```

### Writing Tests

Create test files with naming convention `test_<module>.py`:

```python
import pytest

@pytest.mark.unit
def test_my_feature():
    """Test that my feature works correctly."""
    # Arrange
    input_data = "test"
    
    # Act
    result = my_feature(input_data)
    
    # Assert
    assert result == "expected output"
```

See [TESTING.md](../TESTING.md) for comprehensive testing guidelines.

## 📝 Code Quality Checklist

Before submitting a PR, ensure:

- [ ] Code is formatted with `black` and `isort`
- [ ] Code passes `flake8` linting
- [ ] All tests pass
- [ ] New code has test coverage (80%+ goal)
- [ ] Documentation is updated
- [ ] No hardcoded secrets or sensitive data
- [ ] TODO/FIXME comments include context and issue references
- [ ] Commit messages follow the [50/72 rule](http://tbaggery.com/2008/04/19/a-note-about-git-commit-messages.html)

See [CODE_QUALITY.md](../CODE_QUALITY.md) for detailed guidelines.

## 🔧 Development Tools

### Code Formatting

```bash
# Auto-format Python code
black lib/ modules/

# Sort imports
isort lib/ modules/

# Check Ruby code style
bundle exec rubocop
```

### Linting

```bash
# Python linting
flake8 lib/ modules/

# Ruby linting
bundle exec rubocop

# Type checking (optional)
mypy lib/ modules/
```

### Test Coverage Analysis

```bash
# Analyze test coverage
python3 scripts/check_test_coverage.py

# Generate coverage report
python3 -m pytest --cov=lib --cov=modules --cov-report=html

# View in browser
open htmlcov/index.html  # macOS
xdg-open htmlcov/index.html  # Linux
```

## 🐛 Debugging Tips

### Interactive Debugging

```python
# Add breakpoint in Python code
import pdb; pdb.set_trace()

# Or use IPython debugger
import ipdb; ipdb.set_trace()
```

### Verbose Test Output

```bash
# Show print statements
python3 -m pytest -s

# Verbose output
python3 -m pytest -vv

# Show locals on failure
python3 -m pytest -l
```

## 📦 Module Development

### Creating a New Module

1. Choose appropriate directory:
   - `modules/exploits/` - Exploit modules
   - `modules/auxiliary/` - Auxiliary modules
   - `modules/post/` - Post-exploitation modules
   - `modules/payloads/` - Payload modules

2. Follow naming convention:
   - Platform: `windows/`, `linux/`, `multi/`, etc.
   - Category: `http/`, `smb/`, `ssh/`, etc.
   - Name: descriptive_module_name.py

3. Use module template (see docs/ruby2py/CONVERTER_GUIDE.md)

4. Add module documentation

5. Test thoroughly

6. Submit PR with verification steps

### Module Documentation Template

```python
"""
Exploit Module for CVE-YYYY-XXXXX - Vulnerability Name

This module exploits [brief description of vulnerability] to [what it achieves].

Module Details:
    Name: Descriptive Module Name
    Type: exploit/auxiliary/post
    Platform: Windows/Linux/Multi
    Targets: Software Name X.X-X.X
    CVE: CVE-YYYY-XXXXX
    
References:
    - https://example.com/advisory
    - https://nvd.nist.gov/vuln/detail/CVE-YYYY-XXXXX

Author: Your Name <your.email@example.com>
License: BSD 3-Clause

Usage:
    use exploit/category/module_name
    set RHOSTS target.example.com
    set RPORT 8080
    exploit
    
Verification:
    1. Set up vulnerable software
    2. Configure module options
    3. Run exploit
    4. Verify session established
"""
```

## 🔒 Security Considerations

### Never Commit

- ❌ API keys, tokens, or credentials
- ❌ Private keys or certificates
- ❌ Personally identifiable information (PII)
- ❌ Internal IP addresses or hostnames
- ❌ Sensitive configuration data

### Always Validate

- ✅ User input
- ✅ File paths (prevent traversal)
- ✅ Network data
- ✅ Configuration values
- ✅ External command parameters

### Best Practices

```python
# ✅ Good: Parameterized queries
cursor.execute("SELECT * FROM users WHERE id = ?", (user_id,))

# ❌ Bad: String concatenation
cursor.execute(f"SELECT * FROM users WHERE id = {user_id}")

# ✅ Good: Environment variables for secrets
api_key = os.environ.get('API_KEY')

# ❌ Bad: Hardcoded secrets
api_key = "sk_live_abc123xyz"

# ✅ Good: Validate file paths
if not path.startswith(allowed_dir):
    raise ValueError("Invalid path")

# ❌ Bad: No validation
with open(user_provided_path) as f:
    data = f.read()
```

## 📈 Performance Tips

- Use generators for large data sets
- Cache expensive computations
- Profile code with `cProfile` or `line_profiler`
- Avoid unnecessary loops and operations
- Use appropriate data structures

```python
# ✅ Good: Generator for memory efficiency
def process_large_file(filename):
    with open(filename) as f:
        for line in f:
            yield process_line(line)

# ❌ Bad: Load entire file into memory
def process_large_file(filename):
    with open(filename) as f:
        lines = f.readlines()
    return [process_line(line) for line in lines]
```

## 🤝 Getting Help

### Community Resources

- **GitHub Discussions**: [Ask questions and share ideas](https://github.com/rapid7/metasploit-framework/discussions)
- **Slack**: [Join Metasploit Slack](https://join.slack.com/t/metasploit/shared_invite/...)
- **Documentation**: [Metasploit Docs](https://docs.metasploit.com/)
- **API Docs**: [Framework API](https://rapid7.github.io/metasploit-framework/api/)

### Reporting Issues

- **Bugs**: Use [GitHub Issues](https://github.com/rapid7/metasploit-framework/issues)
- **Security**: Email security@rapid7.com (see [SECURITY.md](../.github/SECURITY.md))
- **Features**: Open a discussion first, then create an issue

## 📖 Common Tasks

### Adding a New Test

```bash
# Create test file
touch test/network/test_my_module.py

# Write test
cat > test/network/test_my_module.py << 'EOF'
import pytest
from lib.network.my_module import MyModule

@pytest.mark.unit
def test_my_module_basic():
    """Test basic functionality."""
    module = MyModule()
    assert module.function() == expected_result
EOF

# Run test
python3 -m pytest test/network/test_my_module.py -v
```

### Updating Documentation

```bash
# Edit relevant .md file
vim TESTING.md

# Preview (if using grip or similar)
grip TESTING.md

# Commit with clear message
git add TESTING.md
git commit -m "docs: Update testing guide with new examples"
```

### Fixing a Bug

```bash
# Create branch
git checkout -b fix/issue-12345-description

# Make changes and add test
vim lib/module.py
vim test/test_module.py

# Verify fix
python3 -m pytest test/test_module.py

# Commit
git add .
git commit -m "fix: Resolve issue #12345 - brief description

Detailed explanation of the bug and fix.

Closes #12345"

# Push and create PR
git push origin fix/issue-12345-description
```

## 🎯 Tips for Success

1. **Start Small**: Begin with documentation fixes or small bug fixes
2. **Read Existing Code**: Learn patterns from existing modules
3. **Ask Questions**: Don't hesitate to ask in Discussions or Slack
4. **Test Thoroughly**: Test edge cases and error conditions
5. **Document Well**: Help others understand your code
6. **Be Patient**: Code review takes time
7. **Stay Respectful**: Be kind and professional
8. **Keep Learning**: Stay updated with security research

## 📋 Pre-Submission Checklist

Before submitting your PR:

- [ ] Code is properly formatted and linted
- [ ] All tests pass locally
- [ ] New tests added for new functionality
- [ ] Documentation updated
- [ ] Commit messages are clear and descriptive
- [ ] Branch is up to date with master
- [ ] No merge conflicts
- [ ] PR description is complete
- [ ] Verification steps provided
- [ ] Related issues referenced

## 🎉 Your First Contribution

Making your first contribution can be intimidating, but remember:

- Everyone started somewhere
- The community is supportive
- Small contributions matter
- Documentation improvements are valuable
- Tests and bug fixes are appreciated

**Good first contributions:**
- Fix typos in documentation
- Add missing docstrings
- Write tests for untested code
- Fix simple bugs
- Improve error messages

Welcome to the Metasploit community! 🚀

## Additional Resources

- [Official Metasploit Documentation](https://docs.metasploit.com/)
- [Module Development Guide](https://docs.metasploit.com/docs/development/developing-modules/)
- [Setting Up Dev Environment](https://docs.metasploit.com/docs/development/get-started/setting-up-a-metasploit-development-environment.html)
- [Python Style Guide (PEP 8)](https://www.python.org/dev/peps/pep-0008/)
- [Ruby Style Guide](https://github.com/bbatsov/ruby-style-guide)
- [Git Commit Message Guide](http://tbaggery.com/2008/04/19/a-note-about-git-commit-messages.html)
