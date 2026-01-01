# Code Cleanliness Review - Documentation

## Overview

The automated Code Cleanliness Review is a workflow that runs every 12 hours to identify code quality issues in the Metasploit Framework. It helps maintain code quality by flagging files that may benefit from refactoring.

## How It Works

The workflow (`.github/workflows/auto-copilot-code-cleanliness-review.yml`) performs the following steps:

1. **Analyzes file sizes**: Identifies files larger than 500 lines
2. **Applies exclusions**: Filters out files that are legitimately large (see Exclusions below)
3. **Creates an issue**: Opens a GitHub issue with the findings
4. **Provides recommendations**: Suggests specific actions to improve code quality

## Exclusions

Not all large files need refactoring. The following types of files are excluded from the review:

### 1. API and Protocol Constants
Files containing large amounts of constant definitions for APIs, error codes, and protocol specifications.

**Examples:**
- `lib/rex/post/meterpreter/extensions/stdapi/railgun/def/windows/api_constants.rb` (38k+ lines)
- `lib/msf/core/post/windows/error.rb` (Windows error codes)
- `lib/rex/proto/smb/constants.rb` (SMB protocol constants)

**Rationale:** These are reference data files that serve as comprehensive lookup tables. Splitting them would reduce usability.

### 2. Reference Data Files
Files containing large lookup tables and reference data.

**Examples:**
- `lib/rex/oui.rb` (MAC address OUI table)
- `lib/msf/core/post/hardware/automotive/dtc.rb` (Diagnostic Trouble Codes)
- `lib/msf/core/mitre/attack/technique.rb` (MITRE ATT&CK mapping)

**Rationale:** These are data files, not code. Their size is determined by the data they contain.

### 3. Protocol Implementations
Files implementing complete protocol specifications or codecs.

**Examples:**
- `lib/rex/proto/iax2/codecs/g711.rb` (Audio codec)
- `lib/rex/proto/kerberos/pac/krb5_pac.rb` (Kerberos PAC structure)

**Rationale:** Protocol implementations need to be complete and often require many related functions.

### 4. Test Files
Comprehensive test suites with many test cases and fixtures.

**Examples:**
- `spec/lib/rex/proto/x11/window.rb` (2941 lines)
- `spec/lib/msf/core/payload_generator_spec.rb` (1393 lines)

**Rationale:** Comprehensive test coverage naturally results in large test files. Splitting tests can make them harder to maintain.

### 5. Vendored Libraries
Third-party code included in the repository.

**Examples:**
- `lib/rbmysql.rb`
- `lib/net/dns/resolver.rb`
- `lib/snmp/manager.rb`

**Rationale:** External libraries should not be modified unless necessary for security or compatibility.

### 6. Generated Files
Auto-generated code and schemas.

**Examples:**
- `db/schema.rb` (Database schema)

**Rationale:** Generated files should be updated by regenerating them, not manually edited.

### 7. Exploit Data
Proof-of-concept exploits and payloads.

**Examples:**
- `data/exploits/CVE-2019-12477/*.ts`
- `data/exploits/CVE-2021-3156/*.py`

**Rationale:** These are standalone exploit implementations, not framework code.

### 8. Build/Development Tools
Tools for building, testing, and maintaining the framework.

**Examples:**
- `tools/dev/msftidy.rb` (Metasploit linter)
- `tools/py2ruby_transpiler.py` (Transpiler)

**Rationale:** Standalone tools with specific purposes that don't benefit from splitting.

## What Files SHOULD Be Reviewed?

Files that are NOT excluded are the ones that should be reviewed for potential refactoring:

- **Core framework code**: Business logic in the Metasploit Framework
- **Module dispatchers**: Command dispatchers and UI code
- **New custom code**: Recently added functionality
- **Complex exploits/modules**: Files with business logic that could be modularized

## Adding New Exclusions

If you encounter a file that you believe should be excluded:

### Step 1: Evaluate the Criteria

Ask yourself:
- [ ] Is this file primarily data/constants? (lookup tables, error codes, etc.)
- [ ] Does it implement a complete protocol or codec specification?
- [ ] Is it third-party/vendored code?
- [ ] Is it auto-generated?
- [ ] Is it a comprehensive test fixture?

**If yes to any:** Consider adding it to exclusions.

**If no:** The file likely contains business logic and should be refactored instead.

### Step 2: Add to Exclusions File

Edit `.github/code-cleanliness-exclusions.yml`:

```yaml
# Add under the appropriate category
category_name:
  - ./path/to/file.rb  # Brief description of why it's excluded
```

### Step 3: Submit a PR

Include:
- The updated exclusions file
- A clear rationale for the exclusion
- Link to any related issues or discussions

## Review Criteria

When reviewing large files flagged by the automated review, consider:

### Metrics for "Should Split"

- **Multiple unrelated responsibilities**: File handles different concerns
- **High cyclomatic complexity**: Many conditional branches and paths
- **Poor testability**: Difficult to write focused unit tests
- **Unclear organization**: Hard to find specific functionality
- **Frequent merge conflicts**: Multiple developers editing different parts

### Metrics for "Keep Together"

- **Single cohesive purpose**: All code relates to one clear responsibility
- **Tightly coupled components**: Splitting would require extensive cross-references
- **Protocol/specification implementation**: Completeness is more important than size
- **Reference data**: Lookup tables, constants, mappings

## Workflow Configuration

The workflow can be triggered:

1. **Automatically**: Every 12 hours (00:00 and 12:00 UTC)
2. **Manually**: Via GitHub Actions "workflow_dispatch"

To modify the schedule, edit `.github/workflows/auto-copilot-code-cleanliness-review.yml`:

```yaml
on:
  schedule:
    - cron: '0 0,12 * * *'  # Modify this line
```

## Interpreting Results

When an issue is created:

### No Files Listed
✅ All large files are appropriately excluded or under the 500-line threshold.

### Files Listed
⚠️ These files exceed 500 lines and are not in the exclusions list. They should be evaluated for refactoring.

## Best Practices

1. **Regular review**: Address findings within a reasonable timeframe
2. **Prioritize by impact**: Focus on frequently modified files first
3. **Incremental refactoring**: Small, focused changes are easier to review
4. **Maintain tests**: Ensure tests pass after refactoring
5. **Document decisions**: If keeping a file large, document why in exclusions

## Related Documentation

- [CODE_QUALITY.md](../CODE_QUALITY.md) - Code quality guidelines
- [CONTRIBUTING.md](../CONTRIBUTING.md) - Contribution guidelines
- [Ruby Style Guide](https://github.com/bbatsov/ruby-style-guide)
- [PEP 8](https://www.python.org/dev/peps/pep-0008/) - Python style guide

## Questions?

- Open a discussion in [GitHub Discussions](https://github.com/rapid7/metasploit-framework/discussions)
- Ask in [Metasploit Slack](https://www.metasploit.com/slack)
- Comment on the automated issue created by the workflow
