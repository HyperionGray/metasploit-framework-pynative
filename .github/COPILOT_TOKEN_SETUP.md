# GitHub Copilot Token Setup Guide

This guide explains how to set up the `COPILOT_TOKEN` repository secret required for GPT-5 code analysis workflows.

## Overview

Some GitHub Actions workflows in this repository use GitHub Copilot's API to perform advanced code analysis using GPT-5 models. These workflows require a GitHub Personal Access Token (PAT) with Copilot access.

## Why This Is Required

- The default `GITHUB_TOKEN` provided by GitHub Actions does not have access to GitHub Copilot APIs
- A personal access token with the `copilot` scope is needed to authenticate with Copilot services
- This token must be stored as a repository secret named `COPILOT_TOKEN`

## Affected Workflows

The following workflows require `COPILOT_TOKEN`:
- `.github/workflows/auto-gpt5-implementation.yml` - GPT-5 code analysis
- `.github/workflows/auto-copilot-code-cleanliness-review.yml` - Code cleanliness reviews
- Other workflows that use `austenstone/copilot-cli-action`

## Setup Instructions

### Step 1: Create a Personal Access Token

1. Go to your GitHub account settings
2. Navigate to **Developer settings** → **Personal access tokens** → **Fine-grained tokens** (or **Tokens (classic)**)
3. Click **Generate new token**
4. Configure the token:
   - **Name**: `Metasploit Framework Copilot Token` (or any descriptive name)
   - **Expiration**: Choose an appropriate expiration period
   - **Scopes**: Enable the `copilot` scope
     - For fine-grained tokens, grant access to the repository
     - For classic tokens, check the `copilot` checkbox

### Step 2: Add Token as Repository Secret

1. Go to the repository on GitHub
2. Navigate to **Settings** → **Secrets and variables** → **Actions**
3. Click **New repository secret**
4. Configure the secret:
   - **Name**: `COPILOT_TOKEN` (must be exactly this name)
   - **Secret**: Paste your personal access token
5. Click **Add secret**

### Step 3: Enable Workflows

After adding the `COPILOT_TOKEN` secret:

1. Open `.github/workflows/auto-gpt5-implementation.yml`
2. Change the trigger from `workflow_dispatch` to the desired triggers:
   ```yaml
   on:
     push:
       branches:
         - main
         - master
     pull_request:
       types: [opened, synchronize, reopened]
     workflow_dispatch:
   ```
3. Commit and push the changes

## Security Considerations

### Token Permissions

- **Minimal Scope**: Only grant the `copilot` scope to the token
- **Repository Access**: For fine-grained tokens, only grant access to repositories that need it
- **Expiration**: Set an appropriate expiration date and rotate tokens regularly

### Best Practices

1. **Never commit tokens**: The token should only exist in GitHub Secrets
2. **Rotate regularly**: Set an expiration date and create a new token before it expires
3. **Monitor usage**: Check GitHub's token usage logs periodically
4. **Revoke if compromised**: If a token is exposed, revoke it immediately

### Important Notes

- Personal access tokens are tied to your GitHub account
- Anyone with access to the token can use your Copilot quota
- The token has the same Copilot access as your account
- Copilot API usage may count against your Copilot subscription limits

## Troubleshooting

### Workflow Fails with "Token not configured" Error

**Problem**: The workflow runs but skips GPT-5 analysis with a warning about missing token.

**Solution**: 
1. Verify the secret is named exactly `COPILOT_TOKEN` (case-sensitive)
2. Ensure the token has the `copilot` scope enabled
3. Check that the token hasn't expired

### Workflow Fails with "401 Unauthorized" Error

**Problem**: The workflow tries to use Copilot but gets authentication errors.

**Solution**:
1. Verify your GitHub account has an active Copilot subscription
2. Check that the token has the correct scope (`copilot`)
3. Ensure the token hasn't been revoked
4. Try creating a new token

### Copilot Analysis Produces No Results

**Problem**: The workflow runs but doesn't produce any meaningful analysis.

**Solution**:
1. Check the workflow logs for errors in the Copilot API steps
2. Verify the `austenstone/copilot-cli-action` action is up to date
3. Ensure your Copilot subscription includes API access

## Alternative: Manual Analysis

If you don't want to set up `COPILOT_TOKEN`, you can still get code analysis:

1. Use GitHub Copilot directly in your IDE (VS Code, JetBrains, etc.)
2. Use Copilot Chat to ask for code reviews
3. Run manual code quality tools (linters, static analysis, etc.)

## Support

For issues related to:
- **GitHub Copilot**: Contact GitHub Support
- **This workflow**: Open an issue in this repository
- **Token setup**: Refer to [GitHub's PAT documentation](https://docs.github.com/en/authentication/keeping-your-account-and-data-secure/managing-your-personal-access-tokens)

## References

- [GitHub Copilot Documentation](https://docs.github.com/en/copilot)
- [Personal Access Tokens Documentation](https://docs.github.com/en/authentication/keeping-your-account-and-data-secure/managing-your-personal-access-tokens)
- [GitHub Actions Secrets](https://docs.github.com/en/actions/security-guides/encrypted-secrets)
- [Supported AI Models](https://docs.github.com/en/copilot/reference/ai-models/supported-models)
