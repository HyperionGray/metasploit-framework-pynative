# GitHub Actions Workflows

This directory contains automated workflows for the Metasploit Framework repository. This document provides an overview of available workflows and their purposes.

## Automated Analysis Workflows

### GPT-5 Code Analysis (`auto-gpt5-implementation.yml`)

**Status**: Manual trigger only (requires COPILOT_TOKEN configuration)

Performs comprehensive code analysis using GitHub Copilot's GPT-5 models.

**Capabilities**:
- Deep code understanding and semantic analysis
- Security vulnerability detection
- Performance optimization recommendations
- Architecture review
- Test coverage analysis

**Requirements**:
- Requires `COPILOT_TOKEN` repository secret to be configured
- See [COPILOT_TOKEN_SETUP.md](../COPILOT_TOKEN_SETUP.md) for setup instructions

**Trigger**: Manual (`workflow_dispatch`)

**To Enable**:
1. Configure `COPILOT_TOKEN` secret (see setup guide)
2. Run manually from Actions tab with "Enable GPT-5 analysis" set to "true"

### Code Cleanliness Review (`auto-copilot-code-cleanliness-review.yml`)

**Status**: Scheduled (every 12 hours)

Analyzes code for cleanliness issues like large files, code duplication, and complexity.

**Capabilities**:
- Identifies large files that may benefit from splitting
- Detects code duplication
- Analyzes code complexity

**Trigger**: Scheduled (cron), Manual (`workflow_dispatch`)

### Functionality Documentation Review (`auto-copilot-functionality-docs-review.yml`)

Reviews code and documentation for completeness and accuracy.

**Trigger**: Scheduled, Manual

### Amazon Q Review (`auto-amazonq-review.yml`)

Uses Amazon Q for code review and suggestions.

**Trigger**: Pull requests, Manual

## CI/CD Workflows

### Complete CI/CD Review (`auto-complete-cicd-review.yml`)

Comprehensive CI/CD pipeline review and validation.

**Trigger**: Pull requests, Scheduled

## Testing Workflows

### Test Suite (`test.yml`)

Runs the main test suite for the repository.

**Trigger**: Push, Pull requests

### Command Shell Acceptance (`command_shell_acceptance.yml`)

Tests command shell functionality.

**Trigger**: Push to main, Pull requests

### Meterpreter Acceptance (`meterpreter_acceptance.yml`)

Tests Meterpreter payload functionality.

**Trigger**: Push to main, Pull requests

### Database Acceptance Tests

Multiple workflows test database integrations:
- `mssql_acceptance.yml` - Microsoft SQL Server
- `mysql_acceptance.yml` - MySQL
- `postgres_acceptance.yml` - PostgreSQL
- `ldap_acceptance.yml` - LDAP

**Trigger**: Push to main, Pull requests

### SMB Acceptance (`smb_acceptance.yml`)

Tests SMB protocol functionality.

**Trigger**: Push to main, Pull requests

### Comprehensive Nightly Tests (`comprehensive-nightly-tests.yml`)

Runs extensive test suite nightly.

**Trigger**: Scheduled (nightly)

## Code Quality Workflows

### Lint (`lint.yml`)

Runs linting checks on code.

**Trigger**: Push, Pull requests

### Verify (`verify.yml`)

Verifies code quality and standards compliance.

**Trigger**: Push, Pull requests

### Shared Gem Verify (`shared_gem_verify.yml`, `shared_gem_verify_rails.yml`)

Verifies shared gems and Rails dependencies.

**Trigger**: Scheduled, Manual

## Security Workflows

### Security Scan (`auto-sec-scan.yml`)

Performs security scanning on the codebase.

**Trigger**: Push, Pull requests, Scheduled

## Documentation Workflows

### Docs (`docs.yml`)

Builds and validates documentation.

**Trigger**: Push, Pull requests

## Automation Workflows

### Auto Assign Copilot (`auto-assign-copilot.yml`)

Automatically assigns Copilot to review pull requests.

**Trigger**: Pull requests

### Auto Assign PR (`auto-assign-pr.yml`)

Automatically assigns reviewers to pull requests.

**Trigger**: Pull requests

### Auto Label (`auto-label.yml`)

Automatically labels issues and pull requests.

**Trigger**: Issues, Pull requests

### Auto Label Comment PRs (`auto-label-comment-prs.yml`)

Labels pull requests based on comments.

**Trigger**: Pull request comments

### Auto Close Issues (`auto-close-issues.yml`)

Automatically closes stale or invalid issues.

**Trigger**: Issues, Scheduled

### Auto Bug Report (`auto-bug-report.yml`)

Processes and labels bug reports.

**Trigger**: Issues

### Auto Feature Request (`auto-feature-request.yml`)

Processes and labels feature requests.

**Trigger**: Issues

## Playwright Testing Workflows

### Copilot Playwright Auto Test (`auto-copilot-playwright-auto-test.yml`)

Automated Playwright testing with Copilot integration.

**Trigger**: Push, Pull requests

### Copilot Playwright Test Review (`auto-copilot-test-review-playwright.yml`)

Reviews Playwright test results.

**Trigger**: Workflow completion

### Copilot Org Playwright Loop (`auto-copilot-org-playwright-loop.yaml`, `auto-copilot-org-playwright-loopv2.yaml`)

Organization-level Playwright testing loops.

**Trigger**: Scheduled, Manual

## Maintenance Workflows

### Schedule Stale (`schedule-stale.yml`)

Marks and closes stale issues and pull requests.

**Trigger**: Scheduled (daily)

### Weekly Data and External Tool Updater (`weekly-data-and-external-tool-updater.yml`)

Updates external data and tools weekly.

**Trigger**: Scheduled (weekly)

### Weekly Dependencies PR (`weekly-dependencies-pr.yml`)

Creates pull requests for dependency updates.

**Trigger**: Scheduled (weekly)

## Cross-Repository Workflows

### Trigger All Repos (`trigger-all-repos.yml`)

Triggers workflows across all related repositories.

**Trigger**: Manual (`workflow_dispatch`)

### Workflows Sync Template Backup (`workflows-sync-template-backup.yml`)

Syncs workflow templates across repositories.

**Trigger**: Scheduled, Manual

## Labels Workflow

### Labels (`labels.yml`)

Manages repository labels.

**Trigger**: Manual, Push

## Configuration Files

### Workflow Configuration

Workflows may reference configuration files in the repository:
- `.github/copilot-instructions.md` - Instructions for GitHub Copilot
- `.github/SECURITY.md` - Security policy
- `.github/PULL_REQUEST_TEMPLATE.md` - PR template
- `.github/ISSUE_TEMPLATE/` - Issue templates

### Secrets Required

Some workflows require repository secrets:
- `COPILOT_TOKEN` - Required for GPT-5 and Copilot analysis workflows
- `GITHUB_TOKEN` - Automatically provided by GitHub Actions
- Other secrets may be required for specific integrations

## Troubleshooting

### Workflow Fails Due to Missing Token

If a workflow fails with token-related errors:
1. Check if the required secret is configured in repository settings
2. Refer to the specific setup guide (e.g., [COPILOT_TOKEN_SETUP.md](../COPILOT_TOKEN_SETUP.md))
3. Verify token hasn't expired

### Workflow Doesn't Trigger

If a workflow doesn't trigger as expected:
1. Check the trigger conditions in the workflow file
2. Verify branch names match (e.g., `main` vs `master`)
3. Check if workflow is disabled in repository settings
4. Review workflow run history in the Actions tab

### Workflow Fails Silently

Some workflows use `continue-on-error: true` to prevent blocking. Check:
1. Workflow logs for warnings and errors
2. Step status (skipped, failed, succeeded)
3. Output artifacts or reports generated

## Contributing

When adding or modifying workflows:
1. Follow existing naming conventions
2. Add appropriate documentation
3. Test workflows in a fork first
4. Use `continue-on-error` sparingly
5. Add proper error handling
6. Document required secrets and permissions

## Support

For workflow-related issues:
- Check the Actions tab for run history and logs
- Review this documentation
- Open an issue with workflow logs attached
- Tag the issue with `ci/cd` label
