# Deprecated Ruby-to-Python Conversion Scripts

## ⚠️ WARNING: DEPRECATED CODE

This directory contains **deprecated** and **obsolete** scripts from the Ruby-to-Python conversion project. These files are **NOT** part of the active codebase.

## Status

- **Purpose**: Historical reference only
- **Maintenance**: No longer maintained
- **Security**: May contain unsafe code patterns
- **Usage**: DO NOT USE in production or new development

## Security Notice

Many scripts in this directory use potentially unsafe patterns including:

- `exec()` calls on file contents
- Dynamic code execution
- Unvalidated file operations

**These patterns were acceptable in a development/conversion context but are NOT suitable for production use.**

## Contents

This directory contains various iterations of conversion scripts that were used during the Ruby-to-Python migration:

- Ruby-to-Python transpilers
- Batch conversion utilities
- Test harnesses for conversion validation
- Intermediate conversion scripts

## Active Conversion Tools

For current conversion tools, see:

- `../convert.py` - Active conversion script
- `/batch_ruby2py_converter.py` - Current batch converter
- `/convert_to_pynative.py` - Main conversion utility

## Conversion Complete

The Ruby-to-Python conversion is **COMPLETE**. See:

- `/RUBY2PY_CONVERSION_COMPLETE.md`
- `/docs/ruby2py/TRANSPILATION_REPORT.md`

These deprecated scripts are kept only for:
1. Historical reference
2. Understanding conversion methodology
3. Potential future reference for similar projects

## If You Need to Use These Files

**Don't.** They are deprecated for good reasons:

1. Modern equivalents exist in the active codebase
2. They may contain security vulnerabilities
3. They were designed for one-time use during migration
4. They are not maintained or tested

If you absolutely must reference them, understand:
- They were tools for a specific conversion task
- Security was not the primary concern (they were dev scripts)
- They should never be used on untrusted input
- They should never be deployed to production systems

## Cleanup Status

These files are retained but may be removed in future cleanup efforts if determined to have no historical value.

## Questions?

See the main project documentation:
- [README.md](/README.md)
- [CONTRIBUTING.md](/CONTRIBUTING.md)
- [docs/SECURITY_BEST_PRACTICES.md](/docs/SECURITY_BEST_PRACTICES.md)

---

*This directory is deprecated as of December 2024. For current development, refer to the active codebase in `/lib`, `/modules`, and other primary directories.*
