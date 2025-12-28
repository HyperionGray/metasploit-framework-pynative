# Security Guidelines for Metasploit Framework

## Overview

This document outlines the security guidelines and best practices for developing and maintaining the Metasploit Framework, particularly focusing on the Python migration and security improvements implemented to address code analysis findings.

## Security Improvements Implemented

### 1. Secure Script Execution Framework

**Problem**: The original framework used `eval()` calls that could execute arbitrary code without validation.

**Solution**: Implemented `SecureScriptExecutor` class with:
- Input validation and sanitization
- Sandboxed execution environments
- Whitelisting of allowed operations and imports
- AST parsing for Python script validation

**Files Modified**:
- `lib/rex/script.rb` - Added security validation
- `lib/rex/script/base.rb` - Enhanced with secure execution
- `lib/msf/core/secure_script_execution.py` - New secure execution framework

### 2. Secure Command Execution Framework

**Problem**: Multiple files contained `exec()` calls that could lead to command injection.

**Solution**: Implemented `SecureCommandExecutor` class with:
- Command validation and sanitization
- Input parameter validation
- Environment variable sanitization
- Timeout handling and resource limits

**Files Created**:
- `lib/msf/core/secure_command_execution.py` - Secure command execution framework

### 3. Enhanced Testing Infrastructure

**Problem**: No pytest configuration and limited security testing.

**Solution**: 
- Created comprehensive pytest configuration (`pytest.ini`)
- Implemented security-focused test suite (`test/security/test_security_comprehensive.py`)
- Added test markers for different types of security tests

## Security Best Practices

### For Developers

#### 1. Script Execution
```python
# ❌ NEVER do this - Direct eval() without validation
eval(user_input)

# ✅ DO this - Use secure execution framework
from msf.core.secure_script_execution import secure_eval
result = secure_eval(validated_input, safe_globals, safe_locals)
```

#### 2. Command Execution
```python
# ❌ NEVER do this - Direct system calls
os.system(f"command {user_input}")

# ✅ DO this - Use secure command execution
from msf.core.secure_command_execution import secure_exec_command
result = secure_exec_command(['command', validated_input])
```

#### 3. File Operations
```python
# ❌ NEVER do this - Unrestricted file access
with open(user_provided_path, 'r') as f:
    content = f.read()

# ✅ DO this - Validate paths and restrict access
from pathlib import Path
safe_path = Path(user_provided_path).resolve()
if safe_path.is_relative_to('/allowed/directory'):
    with open(safe_path, 'r') as f:
        content = f.read()
```

### For Module Development

#### 1. Input Validation
Always validate and sanitize user inputs:
```python
def validate_target_input(target):
    """Validate target input for security"""
    # Check for injection patterns
    dangerous_patterns = [';', '&', '|', '`', '$', '(', ')']
    if any(char in target for char in dangerous_patterns):
        raise ValueError("Invalid characters in target")
    
    # Validate format (e.g., IP address)
    import ipaddress
    try:
        ipaddress.ip_address(target)
    except ValueError:
        raise ValueError("Invalid IP address format")
    
    return target
```

#### 2. Error Handling
Implement secure error handling:
```python
try:
    result = risky_operation()
except SecurityError as e:
    # Log security violations
    logging.warning(f"Security violation: {e}")
    # Don't expose internal details
    raise ModuleError("Operation failed due to security restrictions")
except Exception as e:
    # Log unexpected errors
    logging.error(f"Unexpected error: {e}")
    raise ModuleError("Operation failed")
```

#### 3. Resource Limits
Implement resource limits for operations:
```python
import signal

def timeout_handler(signum, frame):
    raise TimeoutError("Operation timed out")

def safe_operation_with_timeout(operation, timeout=30):
    """Execute operation with timeout"""
    signal.signal(signal.SIGALRM, timeout_handler)
    signal.alarm(timeout)
    try:
        result = operation()
        return result
    finally:
        signal.alarm(0)  # Cancel alarm
```

## Security Testing Guidelines

### 1. Test Categories

Use pytest markers to categorize security tests:
```python
@pytest.mark.security
def test_input_validation():
    """Test input validation security"""
    pass

@pytest.mark.integration
@pytest.mark.security
def test_end_to_end_security():
    """Test end-to-end security"""
    pass
```

### 2. Security Test Patterns

#### Input Validation Tests
```python
def test_malicious_input_blocked():
    """Test that malicious inputs are blocked"""
    malicious_inputs = [
        "'; DROP TABLE users; --",
        "../../../etc/passwd",
        "$(rm -rf /)",
        "`malicious_command`"
    ]
    
    for malicious_input in malicious_inputs:
        with pytest.raises(SecurityError):
            vulnerable_function(malicious_input)
```

#### Command Injection Tests
```python
def test_command_injection_prevention():
    """Test command injection prevention"""
    injection_attempts = [
        "normal_input; rm -rf /",
        "normal_input && malicious_command",
        "normal_input | malicious_command"
    ]
    
    for attempt in injection_attempts:
        with pytest.raises(CommandExecutionError):
            execute_command_safely(attempt)
```

### 3. Running Security Tests

```bash
# Run all security tests
pytest -m security

# Run security tests with coverage
pytest -m security --cov=lib --cov-report=html

# Run specific security test categories
pytest -m "security and unit"
pytest -m "security and integration"
```

## Code Review Security Checklist

### Before Merging Code

- [ ] **Input Validation**: All user inputs are validated and sanitized
- [ ] **No Direct eval()/exec()**: No direct use of eval() or exec() without security framework
- [ ] **Command Execution**: All system commands use secure execution framework
- [ ] **File Access**: File operations are restricted to allowed directories
- [ ] **Error Handling**: Errors don't expose sensitive information
- [ ] **Resource Limits**: Operations have appropriate timeouts and limits
- [ ] **Security Tests**: Security tests are included and passing
- [ ] **Documentation**: Security implications are documented

### Security Review Questions

1. **Can user input reach eval() or exec() functions?**
2. **Are all system commands properly validated?**
3. **Can file paths be manipulated for directory traversal?**
4. **Are there any hardcoded credentials or secrets?**
5. **Do error messages expose sensitive information?**
6. **Are there appropriate resource limits and timeouts?**
7. **Is the code tested against common attack vectors?**

## Incident Response

### Security Vulnerability Reporting

1. **Internal Discovery**: Report to security team immediately
2. **External Report**: Follow responsible disclosure process
3. **Assessment**: Evaluate severity and impact
4. **Mitigation**: Implement immediate fixes
5. **Testing**: Verify fixes don't break functionality
6. **Documentation**: Update security guidelines if needed

### Emergency Response Procedures

1. **Immediate Actions**:
   - Disable affected functionality if possible
   - Assess scope of potential impact
   - Notify security team and maintainers

2. **Investigation**:
   - Analyze attack vectors and root causes
   - Check for similar vulnerabilities
   - Document findings

3. **Remediation**:
   - Implement security fixes
   - Add regression tests
   - Update security guidelines
   - Conduct security review

## Security Tools and Resources

### Static Analysis Tools
- **Bandit**: Python security linter
- **Semgrep**: Multi-language static analysis
- **CodeQL**: Semantic code analysis

### Dynamic Analysis Tools
- **pytest-security**: Security testing plugin
- **safety**: Dependency vulnerability scanner
- **OWASP ZAP**: Web application security testing

### Security Resources
- [OWASP Top 10](https://owasp.org/www-project-top-ten/)
- [CWE/SANS Top 25](https://cwe.mitre.org/top25/)
- [Python Security Guidelines](https://python.org/dev/security/)

## Compliance and Standards

### Security Standards
- Follow OWASP secure coding practices
- Implement CWE mitigation strategies
- Adhere to NIST cybersecurity framework

### Regular Security Activities
- Monthly security code reviews
- Quarterly dependency vulnerability scans
- Annual penetration testing
- Continuous security monitoring

## Contact Information

For security-related questions or to report vulnerabilities:
- **Security Team**: security@metasploit.local
- **Emergency Contact**: security-emergency@metasploit.local
- **Public Disclosure**: Follow responsible disclosure process

---

**Last Updated**: 2025-12-21  
**Version**: 1.0  
**Next Review**: 2026-03-21