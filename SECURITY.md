# Security Policy

## Supported Versions

The Metasploit Framework follows a continuous release model. We recommend always using the latest version from the [Nightly Installers](https://docs.metasploit.com/docs/using-metasploit/getting-started/nightly-installers.html).

| Version | Supported          |
| ------- | ------------------ |
| Latest  | :white_check_mark: |
| Older   | :x:                |

## Reporting a Vulnerability

**Please do not report security vulnerabilities through public GitHub issues.**

### For Metasploit Framework Security Issues

If you discover a security vulnerability in Metasploit Framework itself:

1. **Email**: Send details to [security@rapid7.com](mailto:security@rapid7.com)
2. **Include**: 
   - Description of the vulnerability
   - Steps to reproduce
   - Potential impact
   - Any proof-of-concept code

### For New Vulnerability Research

If you've discovered a **new vulnerability in third-party software** and would like to contribute a Metasploit module:

1. **Request CVE**: If your module describes a new vulnerability, email [cve@rapid7.com](mailto:cve@rapid7.com) for a CVE ID (include your PR number)
2. **Submit Module**: Follow the [Contributing Guidelines](CONTRIBUTING.md)
3. **Module Documentation**: Include clear documentation and setup instructions

### Response Timeline

- **Initial Response**: Within 5 business days
- **Status Updates**: Every 7-14 days until resolution
- **Disclosure**: Coordinated disclosure timeline will be discussed

### Security Best Practices

When using Metasploit Framework:

1. **Authorization**: Only test systems you have explicit permission to test
2. **Updates**: Keep your installation up-to-date
3. **Isolation**: Run in isolated/sandboxed environments when possible
4. **Credentials**: Never commit credentials or sensitive data
5. **Modules**: Review module code before execution

#### Python-Native Code Security (This Fork)

For developers working with Python code in this fork:

1. **Dynamic Code Execution**: Use `eval()` and `exec()` only when absolutely necessary for exploit functionality. Always document why it's needed.
2. **Input Validation**: Validate and sanitize all user inputs, especially when using dynamic code execution.
3. **Deserialization**: Avoid `pickle.loads()` on untrusted data. Use safer alternatives like JSON.
4. **Dependencies**: Keep Python dependencies updated. Check for CVEs before adding new dependencies.
5. **Type Safety**: Use type hints to catch potential security issues during development.
6. **Secret Management**: Use environment variables or secure vaults for credentials. Check `.gitleaksignore` for patterns to avoid.
7. **Code Review**: All Python code changes undergo automated security scanning via GitHub secret scanning and Amazon Q (when configured).

## Security Resources

- [Metasploit Documentation](https://docs.metasploit.com/)
- [Rapid7 Security Advisories](https://www.rapid7.com/security/)
- [Metasploit Blog - Security](https://blog.rapid7.com/tag/metasploit/)

## Hall of Fame

We recognize and appreciate security researchers who responsibly disclose vulnerabilities. Contributors may be acknowledged in:
- Release notes
- This security policy (with permission)
- Metasploit Blog posts

## Legal

Use of Metasploit Framework must comply with all applicable laws. Unauthorized access to computer systems is illegal. Users are responsible for ensuring they have proper authorization before testing any systems.
