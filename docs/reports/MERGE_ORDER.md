# Recommended Pull Request Merge Order

## Phase 1: Critical Configuration Fixes (Unblock Testing)

These PRs fix configuration issues that prevent tests from running:

1. **PR #244** - Fix TOML parsing error from duplicate pytest configuration keys
   - Priority: CRITICAL
   - Reason: Blocks pytest from running
   - Dependencies: None
   
2. **PR #247** - Fix duplicate configurations in pyproject.toml and requirements.txt
   - Priority: CRITICAL  
   - Reason: Validation failures, duplicate dependencies
   - Dependencies: None

3. **PR #248** - Fix duplicate configurations blocking pytest and clean up requirements
   - Priority: CRITICAL
   - Reason: Prevents test execution
   - Dependencies: May conflict with #244 and #247 - merge one approach

**Action**: Choose ONE of #244, #247, or #248 as they address similar issues. Recommend #248 as it appears most comprehensive.

## Phase 2: CI/CD Infrastructure Improvements

4. **PR #246** - Fix CI/CD workflow binary file detection
   - Priority: HIGH
   - Reason: Improves CI/CD accuracy
   - Dependencies: None

5. **PR #245** - Document CI/CD review findings
   - Priority: MEDIUM
   - Reason: Documentation only, no code changes
   - Dependencies: None

## Phase 3: Testing Infrastructure

6. **PR #235** - E2E test: install + run metasploit-framework-pynative
   - Priority: HIGH
   - Reason: Adds important E2E tests
   - Dependencies: Phase 1 config fixes

7. **PR #224** - E2E test improvements
   - Priority: MEDIUM
   - Dependencies: #235

## Phase 4: Documentation and Code Quality

8. **PRs #215-#223, #225-#238** - Code reviews and large-scale migrations
   - Priority: LOW to MEDIUM
   - Reason: Large refactors, need careful review
   - Approach: Evaluate individually after Phases 1-3

## Merge Conflict Risk Assessment

### High Risk (likely conflicts)
- PRs #244, #247, #248 - All modify pyproject.toml and requirements.txt
- Migration series PRs - Touch hundreds of files

### Low Risk
- Documentation-only PRs (#245)
- New file additions (E2E tests)

## Pre-Merge Checklist

For each PR before merging:
- [ ] Review PR description and changes
- [ ] Check for conflicts with main branch
- [ ] Verify CI/CD status (if applicable)
- [ ] Run local tests if possible
- [ ] Confirm no security issues
- [ ] Update CHANGELOG if needed

## Post-Merge Validation

After each phase:
1. Run full test suite
2. Verify build succeeds
3. Check for broken imports or missing files
4. Review CI/CD pipeline results

## Notes

- **Draft PRs**: Many PRs are marked as drafts and may not be ready to merge
- **Amazon Q PRs**: The 14-part migration series should be evaluated as a whole
- **Copilot PRs**: Multiple automated PRs may have overlapping changes
- **Testing**: Critical that Phase 1 is complete before attempting later phases

## Alternative: Squash and Merge Approach

If too many conflicts arise:
1. Create a new branch from main
2. Manually apply changes from high-priority PRs
3. Cherry-pick commits where possible
4. Close old PRs after incorporating changes
5. Create new consolidated PRs for review

## GitHub Merge Queue Usage

If using GitHub's merge queue feature:
1. Add Phase 1 PRs to queue
2. Wait for successful merge and CI
3. Add Phase 2 PRs
4. Continue incrementally

This reduces conflict resolution burden and ensures each merge is validated.
