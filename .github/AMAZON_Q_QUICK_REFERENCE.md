# Amazon Q Code Review - Developer Quick Reference

**Last Updated:** December 28, 2025  
**For:** Contributors and Maintainers  

## What is Amazon Q Code Review?

Amazon Q is an AI-powered code review assistant from AWS that provides:
- Security vulnerability detection
- Performance optimization suggestions
- Architecture pattern recommendations
- AWS best practices guidance

This repository has automated Amazon Q code reviews that run after GitHub Copilot agent workflows complete.

## Quick Start

### For Contributors

When you submit a PR, the Amazon Q review workflow will automatically:
1. Wait for GitHub Copilot agent reviews to complete
2. Analyze the codebase for security, performance, and architecture issues
3. Create or update an issue with findings
4. Post results as workflow artifacts

**Your Action:** Review the created issue and address any high-priority findings.

### For Maintainers

To enable full Amazon Q integration:

1. **Set up AWS credentials** (one-time):
   ```bash
   # Add to repository secrets:
   AWS_ACCESS_KEY_ID=your_access_key
   AWS_SECRET_ACCESS_KEY=your_secret_key
   AWS_REGION=us-east-1  # or your preferred region
   ```

2. **Enable workflows** (if not already enabled):
   - `.github/workflows/auto-amazonq-review.yml`
   - `.github/workflows/auto-complete-cicd-review.yml`

3. **Configure Amazon CodeWhisperer** (optional but recommended):
   - Follow [AWS CodeWhisperer setup](https://aws.amazon.com/codewhisperer/)
   - Enable security scanning
   - Configure alert notifications

## Current Review Status

### What's Working ✓
- ✅ Automated workflow triggers
- ✅ Code structure analysis
- ✅ Security baseline checks
- ✅ Issue creation and tracking
- ✅ Artifact uploads

### What Needs Setup ⏳
- ⏳ AWS credentials for full Amazon Q API access
- ⏳ Amazon CodeWhisperer integration
- ⏳ Custom review rules configuration

## Common Scenarios

### Scenario 1: I just pushed code, when will Amazon Q review it?

The Amazon Q review workflow triggers automatically after:
- GitHub Copilot code cleanliness review completes
- GitHub Copilot test review completes
- GitHub Copilot documentation review completes
- Complete CI/CD pipeline review completes

**Timeline:** Usually within 30-60 minutes of your push.

### Scenario 2: How do I see the review results?

1. **GitHub Issues:** Look for issues labeled `amazon-q`, `automated`, `code-review`
2. **Workflow Artifacts:** Go to Actions → Amazon Q Review → Download artifacts
3. **PR Comments:** Review comments on related PRs (when AWS integration is enabled)

### Scenario 3: The review found security issues, what do I do?

1. **Read the issue** created by the workflow
2. **Assess severity** (Critical, High, Medium, Low)
3. **Fix high-priority items** before merging
4. **Update documentation** if needed
5. **Request re-review** by pushing updates

### Scenario 4: Can I run the review manually?

Yes! Go to Actions → "AmazonQ Review after GitHub Copilot" → Run workflow → Workflow dispatch

### Scenario 5: I disagree with a finding, what should I do?

1. Comment on the issue explaining why
2. Tag maintainers for discussion
3. If it's a false positive, document it
4. Consider updating `.github/workflows/auto-amazonq-review.yml` to exclude the pattern

## Review Categories Explained

### 🔒 Security Considerations
**What it checks:**
- Hardcoded credentials and API keys
- Unsafe use of `eval()`, `exec()`, `pickle.loads()`
- Dependency vulnerabilities (CVEs)
- Input validation gaps
- SQL injection risks
- Command injection risks

**Action if found:**
- **Critical:** Fix immediately before merging
- **High:** Fix within 1 sprint
- **Medium:** Schedule for upcoming work
- **Low:** Document and defer

### ⚡ Performance Optimization
**What it checks:**
- Algorithm complexity (O(n²) → O(n))
- Memory leaks and resource cleanup
- Database query optimization
- Caching opportunities
- Startup time bottlenecks

**Action if found:**
- **High impact:** Add to next sprint
- **Medium impact:** Add to backlog
- **Low impact:** Nice-to-have

### 🏗️ Architecture and Design
**What it checks:**
- Design pattern usage
- Separation of concerns
- Dependency management
- Code duplication
- Module coupling

**Action if found:**
- **Major refactor needed:** Create epic
- **Minor improvements:** Create stories
- **Suggestions:** Document for reference

## Python-Specific Guidelines

### Safe Dynamic Code Execution

```python
# ❌ AVOID: Unsafe eval
user_input = request.get('code')
eval(user_input)  # Security vulnerability!

# ✅ GOOD: Documented and validated
def execute_module(module_name: str, params: dict):
    """
    Execute a Metasploit module with validated parameters.
    Uses eval() for module loading - required for plugin architecture.
    """
    if not is_valid_module_name(module_name):
        raise ValueError("Invalid module name")
    
    # Safe eval with limited scope
    safe_globals = {'__builtins__': {}}
    eval(module_name, safe_globals)
```

### Input Validation

```python
# ❌ AVOID: No validation
def run_command(cmd: str):
    os.system(cmd)

# ✅ GOOD: Validated input with safe execution
def run_command(cmd: str, args: list[str] = None):
    """Run a validated command safely."""
    allowed_commands = {
        'ls': ['-l', '-a', '-h'],
        'pwd': [],
        'whoami': []
    }
    
    if cmd not in allowed_commands:
        raise ValueError(f"Command not allowed: {cmd}")
    
    # Validate arguments if provided
    if args:
        allowed_args = allowed_commands[cmd]
        for arg in args:
            if arg not in allowed_args and not arg.startswith('/safe/path/'):
                raise ValueError(f"Argument not allowed: {arg}")
    
    # Use subprocess with list for safety (no shell injection)
    cmd_list = [cmd] + (args or [])
    subprocess.run(cmd_list, check=True, capture_output=True)
```

### Type Hints

```python
# ❌ AVOID: No type hints
def process_exploit(data):
    return data.decode()

# ✅ GOOD: Clear types
def process_exploit(data: bytes) -> str:
    """Decode exploit data to string."""
    return data.decode('utf-8', errors='replace')
```

## Workflow Files Reference

### Main Amazon Q Workflow
**File:** `.github/workflows/auto-amazonq-review.yml`

**Triggers:**
- After GitHub Copilot workflows complete
- On push to main/master/develop
- Manual dispatch

**What it does:**
1. Waits for Copilot PRs (30 second delay)
2. Prepares code for review
3. Analyzes structure and security
4. Creates GitHub issue with findings
5. Uploads artifacts

### CI/CD Review Pipeline
**File:** `.github/workflows/auto-complete-cicd-review.yml`

**What it does:**
1. Code cleanliness analysis
2. Test execution and review
3. Documentation analysis
4. Build verification
5. Report consolidation
6. Triggers Amazon Q review

## Action Items Tracking

See `.github/AMAZON_Q_ACTION_ITEMS.md` for:
- 23 prioritized action items
- Progress tracking (8 completed, 15 pending)
- Review schedule
- Resources and links

## Metrics Dashboard

### Security Metrics
- **Secrets Found:** 0 (✅ Good)
- **CVEs in Dependencies:** Check `requirements.txt` against CVE database
- **Unsafe Code Patterns:** 47 eval(), 68 exec() (documented usage)

### Code Quality Metrics
- **Total Files:** 16,334
- **Python Files:** 8,351
- **TODO/FIXME Comments:** 50,601
- **Test Coverage:** TBD (pending baseline report)

### Performance Metrics
- **Startup Time:** TBD (pending profiling)
- **Average Module Load Time:** TBD
- **Memory Usage:** TBD

## Useful Commands

### Run Security Checks Locally

```bash
# Check for hardcoded secrets
git secrets --scan

# Check with gitleaks
gitleaks detect --source . --verbose

# Run flake8 for Python linting
flake8 --config .flake8 .

# Run pytest with coverage
pytest --cov=. --cov-report=html
```

### Review Dependencies

```bash
# Check for outdated packages
pip list --outdated

# Check for security vulnerabilities (requires safety)
pip install safety
safety check

# Generate dependency tree
pip install pipdeptree
pipdeptree
```

### Profile Performance

```bash
# Profile Python code
python -m cProfile -o profile.stats your_script.py
python -m pstats profile.stats

# Memory profiling
python -m memory_profiler your_script.py
```

## Getting Help

### Questions About the Review Process
- Open a discussion in [GitHub Discussions](https://github.com/HyperionGray/metasploit-framework-pynative/discussions)
- Ask in the PR comments
- Tag `@maintainers` in issues

### AWS/Amazon Q Configuration Issues
- Check [AWS Documentation](https://aws.amazon.com/q/developer/)
- Review [Amazon CodeWhisperer Setup](https://aws.amazon.com/codewhisperer/)
- Contact repository administrators

### False Positives
- Comment on the issue with explanation
- Provide code context
- Suggest rule updates if appropriate

## Related Documentation

- [Amazon Q Review Response](../AMAZON_Q_REVIEW_RESPONSE.md) - Full findings
- [Action Items Tracker](.github/AMAZON_Q_ACTION_ITEMS.md) - Progress tracking
- [Implementation Summary](.github/AMAZON_Q_IMPLEMENTATION_SUMMARY.md) - Overview
- [Contributing Guidelines](../CONTRIBUTING.md) - Code standards
- [Security Policy](../SECURITY.md) - Security practices

## Tips for Success

1. **Review early:** Don't wait until PR approval to check review findings
2. **Address security first:** Security issues should be fixed before merge
3. **Document decisions:** If you choose not to fix something, document why
4. **Keep dependencies updated:** Regular updates prevent security issues
5. **Write tests:** Good test coverage catches issues early
6. **Use type hints:** They help catch errors before runtime
7. **Follow PEP 8:** Consistent style makes code easier to review

## Troubleshooting

### "Workflow doesn't trigger"
- Check if GitHub Copilot workflows completed successfully
- Verify workflow files are in `.github/workflows/`
- Check Actions tab for any errors

### "No issues created"
- Check if there's an existing recent issue (< 7 days old)
- Look in Actions → Artifacts for reports
- Verify workflow ran successfully

### "AWS integration errors"
- Verify AWS credentials are set in repository secrets
- Check IAM permissions
- Review CloudWatch logs if available

---

**Need Updates?** Submit a PR to improve this guide!  
**Questions?** Open an issue with the `documentation` label.
