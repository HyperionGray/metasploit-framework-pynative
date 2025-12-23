# Amazon Q Integration Guide

## Overview

Amazon Q is AWS's AI-powered coding assistant and code review tool. This guide explains how the Metasploit Framework integrates with Amazon Q for automated code reviews.

## Current Status

**Status:** Placeholder Implementation  
**Workflow:** `.github/workflows/auto-amazonq-review.yml`  
**Integration Level:** Informational reports only

The current implementation:
- ✅ Triggers after GitHub Copilot agent workflows complete
- ✅ Generates structured code review reports
- ✅ Creates GitHub issues with review findings
- ⚠️ Does NOT connect to actual Amazon Q API (pending availability)

## Workflow Triggers

The Amazon Q review workflow triggers after these GitHub Copilot workflows complete:
1. **Periodic Code Cleanliness Review**
2. **Comprehensive Test Review with Playwright**
3. **Code Functionality and Documentation Review**
4. **Org-wide: Copilot Playwright Test, Review, Auto-fix, PR, Merge**
5. **Complete CI/CD Agent Review Pipeline**

It can also be triggered manually via `workflow_dispatch`.

## What the Workflow Does

### 1. Wait for Copilot Agents
- Waits 30 seconds for Copilot agents to complete
- Checks for recent Copilot PRs
- Logs PR information for context

### 2. Prepare Code for Review
- Collects repository metadata
- Lists recent changes (last 10 commits)
- Identifies files changed recently

### 3. Run Code Analysis
Currently performs static analysis:
- Counts source files (Python, JavaScript, TypeScript, Java, Go)
- Generates report structure
- Documents security considerations
- Identifies performance opportunities
- Reviews architecture patterns

### 4. Create GitHub Issue
- Generates a comprehensive review report
- Creates or updates GitHub issue
- Adds labels: `amazon-q`, `automated`, `code-review`, `needs-review`
- Uploads artifacts for 90 days retention

## Setting Up Full Amazon Q Integration

### Prerequisites

1. **Amazon Q Developer Account**
   - Sign up for Amazon Q Developer
   - Obtain AWS credentials with appropriate permissions

2. **AWS IAM Permissions Required**
   ```json
   {
     "Version": "2012-10-17",
     "Statement": [
       {
         "Effect": "Allow",
         "Action": [
           "codewhisperer:*",
           "q:*"
         ],
         "Resource": "*"
       }
     ]
   }
   ```

3. **Repository Secrets**
   Configure these secrets in your GitHub repository:
   - `AWS_ACCESS_KEY_ID`
   - `AWS_SECRET_ACCESS_KEY`
   - `AWS_REGION` (default: us-east-1)

### Installation Steps

#### Step 1: Configure AWS Credentials

```bash
# In GitHub repository settings
Settings → Secrets and variables → Actions → New repository secret

Name: AWS_ACCESS_KEY_ID
Value: <your-access-key>

Name: AWS_SECRET_ACCESS_KEY
Value: <your-secret-key>
```

#### Step 2: Install Amazon Q CLI (When Available)

```bash
# Install AWS CLI v2
curl "https://awscli.amazonaws.com/awscli-exe-linux-x86_64.zip" -o "awscliv2.zip"
unzip awscliv2.zip
sudo ./aws/install

# Configure AWS credentials
aws configure

# Install Amazon Q Developer CLI (pending release)
# This is a placeholder - exact commands will be available when Amazon Q CLI is released
```

#### Step 3: Update Workflow Configuration

Uncomment the Amazon Q integration section in `.github/workflows/auto-amazonq-review.yml`:

```yaml
# Example (when Amazon Q CLI becomes available):
- name: Run Amazon Q Code Review
  run: |
    # Use Amazon Q CLI for code analysis
    aws codewhisperer review \
      --repository-path . \
      --output json > /tmp/amazonq-results.json
    
    # Or use Amazon Q Developer CLI
    amazonq review \
      --path . \
      --format json \
      --output /tmp/amazonq-results.json
```

#### Step 4: Configure Custom Rules

Create `.amazonq/config.yml` in your repository:

```yaml
# Amazon Q configuration for Metasploit Framework
version: 1.0

# Exclude exploit test data and intentional security patterns
exclude:
  - spec/**
  - external/source/**
  - data/exploits/**
  - documentation/modules/**

# Custom rules for penetration testing framework
rules:
  security:
    # Allow intentional security patterns in exploit modules
    allowlist:
      - modules/exploits/**
      - modules/auxiliary/**
      - modules/payloads/**
    
    # Still scan these areas
    blocklist:
      - lib/**
      - config/**
      - tools/**

  performance:
    # Monitor these for optimization opportunities
    monitor:
      - lib/msf/core/**
      - lib/rex/**
      - python_framework/**

  architecture:
    # Design pattern validation
    enforce:
      - factory_pattern: true
      - singleton_pattern: true
      - separation_of_concerns: true

# Severity thresholds
thresholds:
  critical: fail
  high: warn
  medium: info
  low: ignore

# Integration settings
integrations:
  github:
    create_issues: true
    labels:
      - amazon-q
      - automated
      - code-review
    assignees: []
  
  slack:
    enabled: false
    webhook_url: ""
```

#### Step 5: Test the Integration

```bash
# Trigger workflow manually
gh workflow run auto-amazonq-review.yml

# Or via GitHub UI:
# Actions → AmazonQ Review after GitHub Copilot → Run workflow
```

## Understanding the Review Report

### Report Sections

1. **Code Quality Assessment**
   - Code structure analysis
   - File count and organization
   - Module complexity metrics

2. **Security Considerations**
   - Credential scanning results
   - Dependency vulnerabilities
   - Code injection risk analysis

3. **Performance Optimization Opportunities**
   - Algorithm efficiency
   - Resource management
   - Caching opportunities

4. **Architecture and Design Patterns**
   - Design pattern usage
   - Separation of concerns
   - Dependency management

### Action Items

Each review includes actionable items:
- Review findings
- Compare with other tools (Copilot, Snyk, Gitleaks)
- Prioritize based on severity
- Implement fixes
- Update documentation

## Integration with Existing Tools

Amazon Q complements existing code quality tools:

| Tool | Purpose | Status |
|------|---------|--------|
| **RuboCop** | Ruby linting | ✅ Active |
| **msftidy** | Metasploit standards | ✅ Active |
| **Flake8** | Python linting | ✅ Active |
| **Black** | Python formatting | ✅ Active |
| **Snyk** | Dependency scanning | ✅ Active |
| **Gitleaks** | Secret scanning | ✅ Active |
| **GitHub Copilot** | AI code review | ✅ Active |
| **Amazon Q** | AI code analysis | ⚠️ Placeholder |

## Best Practices

### For Developers

1. **Review Reports Regularly**
   - Check Amazon Q issues weekly
   - Prioritize security findings
   - Address performance recommendations incrementally

2. **Use with Other Tools**
   - Run RuboCop and msftidy before commits
   - Review Snyk reports for dependencies
   - Check Gitleaks for accidental secrets

3. **Contribute to Rules**
   - Update `.amazonq/config.yml` as patterns emerge
   - Document intentional security patterns
   - Share false positive patterns with team

### For Maintainers

1. **Configure Thresholds**
   - Adjust severity levels based on module type
   - Set different rules for exploit vs. framework code
   - Balance security with functionality

2. **Monitor Trends**
   - Track metrics over time
   - Identify recurring patterns
   - Prioritize systemic improvements

3. **Update Documentation**
   - Keep integration guide current
   - Document new Amazon Q features
   - Share lessons learned

## Troubleshooting

### Common Issues

**Issue:** "AWS credentials not configured"
```text
Solution: Add secrets to GitHub repository
GitHub UI: Settings → Secrets → Add AWS_ACCESS_KEY_ID and AWS_SECRET_ACCESS_KEY
```

**Issue:** "Amazon Q CLI not found"
```text
Solution: Wait for official Amazon Q CLI release or use AWS CodeWhisperer
Check AWS documentation for latest installation instructions
```

**Issue:** "Too many false positives in exploit modules"
```yaml
# Solution: Update .amazonq/config.yml to exclude exploit modules
exclude:
  - modules/exploits/**
  - modules/auxiliary/**
# Or add specific patterns to allowlist in rules section
```

**Issue:** "Workflow times out"
```yaml
# Solution: Increase timeout in workflow file
jobs:
  amazonq-code-review:
    timeout-minutes: 60  # Increase from default 30
# Or exclude large directories from scanning in .amazonq/config.yml
```

### Getting Help

- **AWS Support:** Contact AWS support for Amazon Q API questions
- **GitHub Discussions:** Post in repository discussions for workflow issues
- **Documentation:** Check AWS documentation for latest Amazon Q features

## Roadmap

### Phase 1: Foundation (Current)
- [x] Create placeholder workflow
- [x] Generate report structure
- [x] Integrate with GitHub Copilot workflows
- [x] Document integration approach

### Phase 2: Basic Integration (Pending Amazon Q API)
- [ ] Configure AWS credentials
- [ ] Install Amazon Q CLI
- [ ] Update workflow with real API calls
- [ ] Test with sample analysis

### Phase 3: Advanced Features
- [ ] Custom rules for Metasploit patterns
- [ ] Automated remediation suggestions
- [ ] Integration with PR reviews
- [ ] Metrics dashboard

### Phase 4: Optimization
- [ ] Performance tuning
- [ ] Incremental scanning
- [ ] Caching strategies
- [ ] Multi-repository support

## Resources

- **Amazon Q Documentation:** https://aws.amazon.com/q/
- **AWS CodeWhisperer:** https://aws.amazon.com/codewhisperer/
- **GitHub Actions:** https://docs.github.com/actions
- **Metasploit Contributing:** `CONTRIBUTING.md`

## Support

For questions or issues:
1. Check existing GitHub issues with `amazon-q` label
2. Review AWS documentation for Amazon Q
3. Post in GitHub Discussions
4. Contact repository maintainers

---
*Last Updated: 2025-12-23*  
*Workflow Version: 1.0 (Placeholder)*  
*Amazon Q API Status: Awaiting availability*
