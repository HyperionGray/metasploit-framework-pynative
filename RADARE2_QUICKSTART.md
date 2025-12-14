# Radare2 Integration - Quick Start Guide

## Overview

This integration brings Radare2's powerful binary analysis capabilities to Metasploit Framework with an intuitive GDB-like interface, LLDB debugging support, coverage-guided fuzzing, and binary instrumentation.

## Installation

### 1. Install Radare2

```bash
# Ubuntu/Debian
sudo apt-get update
sudo apt-get install radare2

# macOS
brew install radare2

# From source (latest version)
git clone https://github.com/radare/radare2
cd radare2
./sys/install.sh
```

### 2. Install Python Dependencies

```bash
# Install required Python packages
pip3 install -r requirements-binary-analysis.txt

# Or manually:
pip3 install r2pipe
```

### 3. Optional: Install LLDB (for dynamic debugging)

```bash
# Ubuntu/Debian
sudo apt-get install lldb python3-lldb

# macOS (included with Xcode)
xcode-select --install

# Or via Homebrew
brew install llvm
```

## Quick Start

### Interactive Debugging (r2gdb)

The easiest way to get started:

```bash
# Launch interactive debugger
python3 tools/binary_analysis/r2gdb.py /bin/ls

# Inside r2gdb:
(r2gdb) info functions          # List all functions
(r2gdb) break main              # Set breakpoint at main
(r2gdb) info registers          # Show registers
(r2gdb) disassemble main        # Disassemble main function
(r2gdb) strings 10              # Find strings (min length 10)
(r2gdb) sections                # Show binary sections
(r2gdb) imports                 # Show imported functions
(r2gdb) quit                    # Exit
```

### Programmatic Usage

```python
#!/usr/bin/env python3
import sys
sys.path.insert(0, 'lib')

from rex.binary_analysis import Radare2Wrapper

# Analyze a binary
with Radare2Wrapper('/path/to/binary') as r2:
    # Get binary information
    info = r2.get_binary_info()
    print(f"Architecture: {info.get('bin', {}).get('arch')}")
    
    # List functions
    functions = r2.list_functions()
    print(f"Found {len(functions)} functions")
    
    # Find strings
    strings = r2.find_strings(min_length=10)
    for s in strings[:10]:
        print(s.get('string'))
    
    # Disassemble
    code = r2.disassemble('main', lines=20)
    print(code)
```

### Run Examples

```bash
# See comprehensive examples
python3 tools/binary_analysis/examples.py /bin/ls

# This will demonstrate:
# - Static analysis with Radare2
# - Binary information extraction
# - Function listing
# - String finding
# - Control flow analysis
# - Instrumentation setup
```

## Common Use Cases

### 1. Reverse Engineering

```bash
python3 tools/binary_analysis/r2gdb.py suspicious_binary

(r2gdb) info functions          # Find interesting functions
(r2gdb) strings 8               # Look for interesting strings
(r2gdb) imports                 # Check what libraries it uses
(r2gdb) xrefs to 0x1234         # Find cross-references
(r2gdb) disassemble 0x1000 50   # Disassemble suspicious code
```

### 2. Vulnerability Research

```python
from rex.binary_analysis import BinaryInstrumentor

# Find interesting functions to analyze
with BinaryInstrumentor('target', use_lldb=False) as inst:
    interesting = inst.find_interesting_functions(['parse', 'decode', 'handle'])
    
    for func in interesting:
        print(f"Analyzing: {func['name']}")
        cfg = inst.analyze_control_flow(hex(func['offset']))
        print(f"  Complexity: {len(cfg['blocks'])} blocks, {len(cfg['edges'])} edges")
```

### 3. Coverage-Guided Analysis

```python
from rex.binary_analysis import BinaryInstrumentor

# Trace execution and track coverage
with BinaryInstrumentor('target', use_lldb=True) as inst:
    # Instrument target function
    inst.instrument_function('parse_input')
    
    # Trace execution
    trace = inst.trace_execution(max_steps=1000)
    
    # Get coverage report
    report = inst.get_coverage_report()
    print(f"Blocks covered: {report['coverage']['blocks_hit']}")
    print(f"Edges covered: {report['coverage']['edges_hit']}")
```

### 4. Fuzzing (Conceptual)

```python
from rex.binary_analysis import InMemoryFuzzer

# Create fuzzer for target function
fuzzer = InMemoryFuzzer('target_binary', 'parse_function')

# Add seed inputs
fuzzer.add_seed(b'valid input')
fuzzer.add_seed(b'edge case')
fuzzer.add_seeds_from_directory('./seeds')

# Fuzz
fuzzer.fuzz(iterations=10000, duration=300)  # 10k iterations or 5 minutes

# Save results
fuzzer.save_crashes('./crashes')
fuzzer.save_corpus('./corpus')
```

## Command Reference

### r2gdb Commands

| Command | Alias | Description |
|---------|-------|-------------|
| `break <addr>` | `b` | Set breakpoint |
| `run` | `r` | Start execution |
| `continue` | `c` | Continue execution |
| `step` | `s` | Step into |
| `stepi` | `si` | Step one instruction |
| `next` | `n` | Step over |
| `nexti` | `ni` | Step over one instruction |
| `backtrace` | `bt` | Show call stack |
| `info registers` | `i reg` | Show registers |
| `info functions` | `i func` | List functions |
| `info breakpoints` | `i break` | List breakpoints |
| `print <addr>` | `x` | Examine memory |
| `disassemble [addr]` | `disas` | Disassemble code |
| `list` | `l` | List current function |
| `delete <addr>` | | Delete breakpoint |
| `set <reg> <val>` | | Set register |
| `get <reg>` | | Get register |
| `strings [min]` | | Find strings |
| `xrefs to/from <addr>` | | Find xrefs |
| `seek <addr>` | | Seek to address |
| `sections` | | Show sections |
| `symbols` | | Show symbols |
| `imports` | | Show imports |
| `exports` | | Show exports |
| `analyze <addr>` | | Analyze function |
| `r2 <cmd>` | | Execute raw r2 command |
| `quit` | `q`, `exit` | Exit debugger |

## Architecture

```
lib/rex/binary_analysis/
├── __init__.py              # Module exports
├── radare2_wrapper.py       # GDB-like Radare2 interface
├── lldb_debugger.py         # LLDB integration
├── instrumentor.py          # Binary instrumentation & coverage
└── fuzzer.py                # In-memory fuzzer

tools/binary_analysis/
├── r2gdb.py                 # Interactive debugger
├── examples.py              # Usage examples
└── README.md                # Detailed documentation

test/binary_analysis/
└── test_binary_analysis.py  # Unit tests
```

## Troubleshooting

### "r2pipe not installed"

```bash
pip3 install r2pipe
```

### "LLDB not available"

LLDB is optional. For static analysis, you don't need it.

```bash
# Ubuntu/Debian
sudo apt-get install lldb python3-lldb

# macOS
xcode-select --install
```

### "radare2 command not found"

```bash
# Install Radare2
sudo apt-get install radare2  # Ubuntu/Debian
brew install radare2           # macOS
```

### Analysis takes too long

- Use smaller binaries for testing
- Reduce analysis depth in Radare2
- Set reasonable limits on trace length

### Permission denied

```bash
# Make scripts executable
chmod +x tools/binary_analysis/*.py
```

## Advanced Topics

### Custom Mutation Strategies

Extend the Mutator class with your own strategies:

```python
from rex.binary_analysis.fuzzer import Mutator

class CustomMutator(Mutator):
    def custom_strategy(self, data):
        # Your custom mutation logic
        return mutated_data
```

### Integration with Metasploit Modules

Use in post-exploitation modules:

```ruby
# In a Meterpreter script
def analyze_binary(binary_path)
  print_status("Analyzing binary...")
  cmd = "python3 lib/rex/binary_analysis/radare2_wrapper.py #{binary_path}"
  output = cmd_exec(cmd)
  print_good("Analysis complete")
end
```

### Coverage Visualization

Export coverage data for visualization:

```python
inst.export_coverage('coverage.json')
# Use with coverage visualization tools
```

## Performance Tips

1. **Static analysis first** - Faster for reconnaissance
2. **Limit trace length** - Set reasonable max_steps
3. **Targeted fuzzing** - Focus on specific functions
4. **Parallel execution** - Run multiple fuzzer instances
5. **Corpus management** - Keep corpus small and diverse

## Contributing

See the main [CONTRIBUTING.md](../../CONTRIBUTING.md) for guidelines.

For binary analysis specific contributions:
1. Follow existing code patterns
2. Add docstrings and type hints
3. Include examples in docstrings
4. Update tests
5. Update documentation

## Resources

- [Radare2 Book](https://book.rada.re/)
- [LLDB Documentation](https://lldb.llvm.org/)
- [AFL Fuzzer](https://github.com/google/AFL)
- [GDB Documentation](https://sourceware.org/gdb/current/onlinedocs/gdb)
- [Metasploit Documentation](https://docs.metasploit.com/)

## License

This integration follows the Metasploit Framework licensing (BSD-3-Clause).

## Support

- GitHub Issues: Report bugs and request features
- Metasploit Slack: Real-time community support
- GitHub Discussions: General questions and discussion
