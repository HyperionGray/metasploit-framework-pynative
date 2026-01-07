# Transpiler Tools Directory (Legacy)

This directory contains legacy/experimental conversion tooling.

**Canonical conversion tools live at the repo root in `ruby2py/`.**
Use that directory (or the small wrappers in `tools/`) as the single source of truth.

## Structure

- `ruby2py/` (repo root) - Ruby→Python converter (`ruby2py/convert.py`)
- `ruby2py/py2ruby/` (repo root) - Python→Ruby transpiler (`ruby2py/py2ruby/transpiler.py`)
- `tools/ruby2py_convert.py` - Convenience wrapper for Ruby→Python
- `tools/py2ruby_transpiler.py` - Convenience wrapper for Python→Ruby

## Usage

See `ruby2py/README.md` for the up-to-date entry points and examples.
