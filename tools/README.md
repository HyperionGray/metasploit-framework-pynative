This folder contains standalone scripts that can help developers and users with various tasks.

## Helpers

- `tools/run_elf_phased.py` - Runs an ELF in time slices (SIGSTOP/SIGCONT) with simple Python steps in-between.

## Transpilers (Canonical)

The canonical Ruby↔Python conversion tools live at the repo root in `ruby2py/`.
This directory provides convenience wrappers:

- `tools/ruby2py_convert.py` → runs `ruby2py/convert.py`
- `tools/py2ruby_transpiler.py` → runs `ruby2py/py2ruby/transpiler.py`
