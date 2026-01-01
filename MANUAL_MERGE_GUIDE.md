# Manual PR Merge Instructions

## Overview
This guide provides step-by-step instructions for manually merging the 62 open pull requests in the metasploit-framework-pynative repository.

## Prerequisites

1. **GitHub Repository Access**
   - Admin or maintainer permissions on the repository
   - Ability to merge pull requests

2. **Local Development Setup**
   ```bash
   # Clone repository
   git clone https://github.com/HyperionGray/metasploit-framework-pynative.git
   cd metasploit-framework-pynative
   
   # Install dependencies
   pip install -r requirements.txt
   
   # Verify tests work
   pytest || python -m pytest
   ```

3. **Tools**
   - Git
   - GitHub CLI (optional but recommended): `gh`
   - Python 3.12+ with pytest

## Method 1: GitHub Web Interface (Recommended for First-Time)

### Step 1: Review and Prioritize

1. Go to https://github.com/HyperionGray/metasploit-framework-pynative/pulls
2. Review open PRs
3. Start with high-priority PRs (config fixes)

### Step 2: Merge Configuration Fixes First

Choose ONE of these PRs (they address the same issue):

**Option A: PR #248** (Most Comprehensive)
1. Navigate to https://github.com/HyperionGray/metasploit-framework-pynative/pull/248
2. Review the changes
3. Check CI status (if available)
4. Click "Merge pull request"
5. Choose merge method: "Squash and merge" (recommended)
6. Confirm merge

**Alternative: PR #247 or PR #244**
- If #248 has issues, try #247 or #244
- Merge using same process

### Step 3: Verify After First Merge

After merging the config fix:

```bash
# Pull latest changes
git pull origin master

# Run tests
pytest

# Check for errors
echo $?  # Should be 0 if tests pass
```

### Step 4: Continue with Next Phases

After successful validation:

1. **PR #246** - CI/CD workflow fixes
2. **PR #245** - Documentation (low risk)
3. **PR #235** - E2E tests
4. **PR #224** - Additional E2E tests

For each:
- Check for conflicts (GitHub will show this)
- Resolve conflicts if needed
- Run tests after merging
- Continue to next

## Method 2: Using GitHub CLI

### Setup
```bash
# Install GitHub CLI (if needed)
# macOS: brew install gh
# Linux: See https://cli.github.com/

# Authenticate
gh auth login

# Navigate to repository
cd metasploit-framework-pynative
```

### Merge Process

```bash
# View PR details
gh pr view 248 --web

# Check if mergeable
gh pr view 248 --json mergeable,state,isDraft

# Merge PR (squash and merge)
gh pr merge 248 --squash --delete-branch

# Pull changes locally
git pull origin master

# Run tests
pytest

# If tests pass, continue with next PR
gh pr merge 246 --squash --delete-branch
```

### Batch Processing (Advanced)

```bash
# Create a list of PRs to merge
PRIORITY_PRS=(248 246 245 235 224)

for pr in "${PRIORITY_PRS[@]}"; do
    echo "Processing PR #$pr..."
    
    # Check status
    status=$(gh pr view "$pr" --json mergeable,state --jq '.state')
    
    if [ "$status" == "OPEN" ]; then
        # Attempt merge
        if gh pr merge "$pr" --squash --auto; then
            echo "Merged PR #$pr"
            sleep 10  # Wait for CI
        else
            echo "Could not auto-merge PR #$pr - requires manual attention"
            break
        fi
    fi
done
```

## Method 3: Git Command Line (Manual Control)

For PRs with conflicts or that need careful review:

```bash
# Ensure you're on master and up to date
git checkout master
git pull origin master

# Create a working branch
git checkout -b merge-pr-248

# Fetch the PR branch
git fetch origin pull/248/head:pr-248

# Merge the PR branch
git merge pr-248

# If conflicts occur:
# 1. Resolve conflicts in files
# 2. git add <resolved-files>
# 3. git commit

# Run tests
pytest

# If tests pass, push to master
git checkout master
git merge merge-pr-248
git push origin master

# Clean up
git branch -D merge-pr-248 pr-248
```

## Handling Conflicts

### Common Conflict Files
- `pyproject.toml` - Multiple PRs modify this
- `requirements.txt` - Duplicate dependency declarations
- `.gitignore` - Testing artifact additions

### Resolution Strategy

1. **For pyproject.toml conflicts:**
   ```bash
   # Open file and look for:
   <<<<<<< HEAD
   [existing content]
   =======
   [new content]
   >>>>>>> pr-branch
   
   # Keep unique configurations from both sides
   # Remove duplicates
   # Ensure valid TOML syntax
   ```

2. **For requirements.txt conflicts:**
   ```bash
   # Merge both versions
   # Remove duplicates
   # Sort alphabetically
   # Keep highest version numbers
   ```

3. **Test after resolving:**
   ```bash
   # Validate configuration
   python -m toml.decoder pyproject.toml  # Should not error
   pip install -r requirements.txt  # Should work
   pytest  # Should run
   ```

## Post-Merge Checklist

After each merge or batch of merges:

- [ ] Pull latest changes: `git pull origin master`
- [ ] Install any new dependencies: `pip install -r requirements.txt`
- [ ] Run linters (if configured): `flake8`, `pylint`, etc.
- [ ] Run test suite: `pytest`
- [ ] Check for import errors: `python -c "import lib.msf"`
- [ ] Review CI/CD pipeline results
- [ ] Update CHANGELOG.md if appropriate
- [ ] Notify team of merged changes

## Dealing with Large Migration PRs (#215-#238)

These are 14-part Ruby-to-Python migration PRs. Special considerations:

### Assessment First
1. Check if they're truly ready to merge (many are drafts)
2. Review scope and dependencies between parts
3. Verify tests exist for migrated code

### Recommended Approach
1. **Don't merge yet** - Wait until Phase 1-3 complete
2. **Review individually** - Each part is substantial
3. **Consider sequencing** - Parts may need to be merged in order
4. **Test thoroughly** - Major architectural changes
5. **Plan rollback** - Be prepared to revert if issues arise

### Alternative Strategy
Instead of merging all migration PRs:
1. Create a single integration branch
2. Cherry-pick needed changes
3. Create new PR with consolidated changes
4. Close old migration PRs with reference to new PR

## Troubleshooting

### "PR is not mergeable"
- Check for conflicts
- Ensure base branch is correct
- Verify CI checks passed
- Check if PR is draft status

### "Tests fail after merge"
- Review what was merged
- Check for missing dependencies
- Look for breaking changes
- Consider reverting: `git revert <commit-hash>`

### "Too many conflicts"
- Consider merging in smaller batches
- Use "ours" strategy for config files: `git checkout --ours <file>`
- Manually reconcile changes
- Ask PR author for help

## Getting Help

If you encounter issues:

1. **Check PR comments** - Author may have left notes
2. **Review related issues** - Look for linked issues
3. **Contact PR author** - Ask for clarification
4. **Repository maintainers** - Escalate if needed

## Final Notes

- **Take your time** - 62 PRs is a lot
- **Test frequently** - Catch issues early
- **Document progress** - Keep track of what's merged
- **Communicate** - Update team on progress
- **Be prepared to revert** - Have backups/branches

## Progress Tracking

Create a checklist to track progress:

```markdown
## Merge Progress

### Phase 1: Critical Fixes
- [ ] PR #248 (or #247 or #244)

### Phase 2: Infrastructure  
- [ ] PR #246
- [ ] PR #245

### Phase 3: Testing
- [ ] PR #235
- [ ] PR #224

### Phase 4: Migrations (Review individually)
- [ ] PR #215
- [ ] PR #216
... (continue list)
```

## Automation Option

For large-scale merging, consider GitHub Actions workflow:

```yaml
name: Auto Merge PRs
on:
  workflow_dispatch:
    inputs:
      pr_numbers:
        description: 'Comma-separated PR numbers'
        required: true

jobs:
  merge:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v3
      - name: Merge PRs
        env:
          GITHUB_TOKEN: ${{ secrets.GITHUB_TOKEN }}
        run: |
          for pr in ${PR_NUMBERS//,/ }; do
            gh pr merge $pr --squash --auto || echo "Failed: $pr"
          done
```

This provides a more controlled, automated approach with proper logging and can be run incrementally.
