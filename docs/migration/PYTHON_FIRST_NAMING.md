# Python-First Naming Convention

As of December 2025, **metasploit-framework-pynative** has adopted a Python-first naming convention.

## Naming Convention

### ✅ Python Files (Primary)
- **No extension** for executables and scripts
- Examples: `msfconsole`, `msfd`, `msfdb`, `msfrpc`, `msfrpcd`, `msfupdate`, `msfvenom`
- These are now the PRIMARY executables that users should invoke

### 🔴 Ruby Files (Deprecated)
- **`.rb` extension** for all Ruby files
- Examples: `msfconsole.rb`, `msfd.rb`, `msfdb.rb`, etc.
- These are maintained temporarily for compatibility
- **Ruby will be deleted soon**

## Rationale

This is **pynative** metasploit. The naming convention reflects that Python is the primary language:

1. **User Experience**: Users type `msfconsole` (not `msfconsole.py`)
2. **Python Standard**: Python executable scripts typically have no extension
3. **Ruby Deprecation**: Ruby files are clearly marked with `.rb` extension
4. **Gradual Migration**: Ruby implementations are kept temporarily but clearly marked as deprecated

## Migration Path

### Current State
```bash
# Python (primary)
./msfconsole    # Python wrapper, delegates to Ruby for now
./msfd          # Python wrapper
./msfdb         # Python wrapper
./msfrpc        # Python wrapper
./msfrpcd       # Python wrapper
./msfupdate     # Python wrapper
./msfvenom      # Full Python implementation

# Ruby (deprecated)
./msfconsole.rb # Original Ruby implementation
./msfd.rb       # Original Ruby implementation
# ... etc
```

### Future State (after Ruby removal)
```bash
# Python (full implementations)
./msfconsole    # Full Python implementation
./msfd          # Full Python implementation
./msfdb         # Full Python implementation
# ... etc

# Ruby files deleted
```

## Implementation Details

### Python Executables
Each Python executable:
1. Has Python shebang: `#!/usr/bin/env python3`
2. Has proper UTF-8 encoding: `# -*- coding: utf-8 -*-`
3. Delegates to corresponding `.rb` file temporarily
4. Will be replaced with full Python implementation when Ruby is removed

### Example: msfconsole
```python
#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import sys
import os
from pathlib import Path

def main():
    # Delegate to Ruby version (msfconsole.rb) for now
    ruby_msfconsole = Path(__file__).parent / "msfconsole.rb"
    if ruby_msfconsole.exists():
        os.execv(str(ruby_msfconsole), ['msfconsole'] + sys.argv[1:])
    else:
        print("Error: Ruby msfconsole not found", file=sys.stderr)
        sys.exit(1)

if __name__ == "__main__":
    main()
```

## For Developers

### When writing new code:
- Use Python (no extension for executables)
- Do NOT use `.py` extension for executable scripts
- Follow Python best practices

### When updating existing code:
- Ruby files: Keep `.rb` extension
- Python files: Remove `.py` extension for executables
- Update references to use new naming convention

### When referencing executables:
```bash
# ✅ Correct
./msfconsole
./msfd
./msfvenom

# ❌ Incorrect (old naming)
./msfconsole.py
./msfd.py
./msfvenom.py
```

## Tools and Utilities

The ruby2py transpiler is available to convert Ruby code to Python:
- `batch_ruby2py_converter.py` - Batch convert Ruby files
- `tools/ast_transpiler/ast_translator.py` - AST-based transpilation
- `transpiler/ruby2py/` - Various transpilation tools

## Status

✅ **Conversion Complete** - All main executables have been renamed  
✅ **Documentation Updated** - All docs reflect new naming convention  
⏳ **Ruby Deprecation** - Ruby files marked with `.rb` extension  
🔜 **Full Python Implementation** - Native Python implementations coming soon

---

**Note**: This is an intermediate state during the Python migration. Ruby implementations (`.rb` files) will be removed in future releases once full Python implementations are complete.
