# Repository Cleanup Summary

This document describes the repository reorganization performed to address the issue: "cleanup on aisle EVERYTHING".

## Problem

The repository root contained 309 files including:
- 182 Python scripts (mostly conversion tools)
- 33 shell scripts
- 50 documentation files (mostly conversion-related)
- 30 test files
- Various miscellaneous files

This made the repository difficult to navigate and understand.

## Solution

Files were reorganized into a logical structure with clear separation of concerns.

## Changes Made

### 1. Ruby-to-Python Conversion Tools → `ruby2py/`

All Ruby-to-Python conversion tools were moved to the `ruby2py/` directory:

```
ruby2py/
├── convert.py          # Main converter (runnable)
├── py2ruby/            # Python→Ruby transpiler
│   ├── transpiler.py
│   └── README.md
├── deprecated/         # Old conversion scripts (170 files)
└── README.md           # Usage documentation
```

**Key runnable file**: `python3 ruby2py/convert.py <input.rb>`

### 2. Documentation → `docs/`

All documentation files moved to organized docs structure:

```
docs/
├── *.md                # General documentation (39 files)
└── ruby2py/            # Conversion-specific docs (15 files)
    ├── CONVERTER_GUIDE.md
    ├── PYTHON_QUICKSTART.md
    ├── TRANSPILATION_REPORT.md
    └── ...
```

### 3. Deprecated/Old Files → `bak/`

Shell scripts, test files, and miscellaneous files moved to backup:

```
bak/
├── *.sh                # Shell scripts (33 files)
├── *_test.py          # Test files (18 files)
├── transpilers/        # Old transpilers directory
└── *.jar, *.pf, etc.  # Miscellaneous files
```

### 4. Root Directory Cleanup

**Before**: 309 files at root level  
**After**: 32 files at root level (core project files only)

Files kept at root:
- Core config: `Gemfile`, `Rakefile`, `pyproject.toml`, `requirements.txt`
- Documentation: `README.md`, `CODE_OF_CONDUCT.md`, `CONTRIBUTING.md`
- License files: `LICENSE`, `LICENSE_GEMS`, `COPYING`
- Docker: `Dockerfile`, `docker-compose.yml`
- MSF executables: `msfconsole`, `msfvenom`, etc.
- Python config: `conftest.py`, `tasks.py`

## File Statistics

| Category | Before (root) | After (root) | Moved To |
|----------|---------------|--------------|----------|
| Python scripts | 182 | 3 | `ruby2py/deprecated/` |
| Shell scripts | 33 | 0 | `bak/` |
| Documentation | 50 | 3 | `docs/` & `docs/ruby2py/` |
| Test files | 30 | 0 | `bak/` |
| Misc files | 32 | 0 | `bak/` |
| **Total** | **309+** | **32** | - |

## Quick Reference

### Using Ruby-to-Python Conversion

```bash
# Convert Ruby module to Python
python3 ruby2py/convert.py modules/exploits/example.rb

# With output file
python3 ruby2py/convert.py input.rb -o output.py

# Convert Python back to Ruby
python3 ruby2py/py2ruby/transpiler.py script.py -o output.rb
```

See [ruby2py/README.md](../ruby2py/README.md) for complete documentation.

### Finding Documentation

- **Ruby2Py conversion**: [docs/ruby2py/](ruby2py/)
- **General docs**: [docs/](.)
- **Main README**: [README.md](../README.md)

### Accessing Backup Files

Files in `bak/` are kept for reference only. See [bak/README.md](../bak/README.md).

## Installation

No changes to installation process. Still use:

```bash
# Python dependencies
pip3 install -r requirements.txt

# Ruby dependencies (if needed)
bundle install
```

## Benefits

1. **Clean root directory**: Easy to see core project structure
2. **Organized conversion tools**: All in `ruby2py/` with clear entry point
3. **Centralized documentation**: All docs in `docs/` directory
4. **Preserved history**: Old files backed up in `bak/` directory
5. **Clear paths**: Updated README with new file locations

## Impact

- ✅ No functionality removed
- ✅ All tools still accessible and working
- ✅ Documentation preserved and organized
- ✅ Path references in README.md updated
- ✅ Conversion tools tested and verified working

## Related Documentation

- [ruby2py/README.md](../ruby2py/README.md) - Conversion tools usage
- [bak/README.md](../bak/README.md) - Backup directory contents
- [README.md](../README.md) - Main project documentation
