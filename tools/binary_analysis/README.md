# Binary Analysis Tools - Radare2 Integration

This directory contains advanced binary analysis tools that integrate Radare2, LLDB, and custom instrumentation for penetration testing and security research.

## Overview

The binary analysis suite provides:

1. **GDB-like Interface to Radare2** - Intuitive debugging commands
2. **LLDB Integration** - Dynamic debugging capabilities
3. **Binary Instrumentation** - Coverage tracking and code path analysis
4. **In-Memory Fuzzer** - High-speed fuzzing with stack manipulation

## Tools

### r2gdb.py - Interactive Debugger

Interactive command-line interface that wraps Radare2 with familiar GDB commands.

**Usage:**
```bash
python3 tools/binary_analysis/r2gdb.py <binary_path>
```

**Commands:**
- `break <addr>` / `b <addr>` - Set breakpoint
- `run` / `r` - Start execution
- `continue` / `c` - Continue execution
- `step` / `s` - Step into
- `stepi` / `si` - Step one instruction
- `next` / `n` - Step over
- `nexti` / `ni` - Step over one instruction
- `backtrace` / `bt` - Show call stack
- `info registers` - Show registers
- `info functions` - List functions
- `info breakpoints` - List breakpoints
- `print <addr>` / `x <addr>` - Examine memory
- `disassemble [addr]` - Disassemble code
- `strings [min_len]` - Find strings
- `sections` - Show binary sections
- `symbols` - Show symbols
- `imports` - Show imports
- `exports` - Show exports

**Example Session:**
```
$ python3 tools/binary_analysis/r2gdb.py /bin/ls

(r2gdb) info functions
Found 123 functions:
0x00001060           entry0
0x00001090           main
...

(r2gdb) break main
Breakpoint set at main

(r2gdb) run
...

(r2gdb) info registers
rax        = 0x00007fffffffe4a8
rbx        = 0x0000000000000000
...

(r2gdb) disassemble
...

(r2gdb) quit
```

## Library Components

### rex.binary_analysis.Radare2Wrapper

Python wrapper for Radare2 with GDB-compatible command interface.

**Usage:**
```python
from rex.binary_analysis import Radare2Wrapper

with Radare2Wrapper('/path/to/binary') as r2:
    # Set breakpoint
    r2.break_at('main')
    
    # Get functions
    functions = r2.list_functions()
    
    # Disassemble
    code = r2.disassemble('0x1000', lines=20)
    
    # Find strings
    strings = r2.find_strings(min_length=8)
    
    # Analyze control flow
    info = r2.get_binary_info()
```

### rex.binary_analysis.LLDBDebugger

LLDB integration for dynamic debugging.

**Usage:**
```python
from rex.binary_analysis import LLDBDebugger

with LLDBDebugger('/path/to/binary', args=['arg1', 'arg2']) as dbg:
    # Set breakpoint
    bp_id = dbg.set_breakpoint('main')
    
    # Run to breakpoint
    dbg.continue_exec()
    
    # Get registers
    regs = dbg.get_registers()
    print(f"RIP: 0x{regs['rip']:x}")
    
    # Read memory
    data = dbg.read_memory(0x1000, 256)
    
    # Get backtrace
    bt = dbg.get_backtrace()
    for frame in bt:
        print(f"{frame['function']} @ 0x{frame['pc']:x}")
```

### rex.binary_analysis.BinaryInstrumentor

Code coverage and instrumentation for analysis.

**Usage:**
```python
from rex.binary_analysis import BinaryInstrumentor

# Static analysis with Radare2
with BinaryInstrumentor('/path/to/binary', use_lldb=False) as inst:
    # Find interesting functions
    interesting = inst.find_interesting_functions(['parse', 'handle'])
    
    # Analyze control flow
    cfg = inst.analyze_control_flow('0x1000')
    print(f"Blocks: {len(cfg['blocks'])}")
    print(f"Edges: {len(cfg['edges'])}")
    
    # Get coverage report
    report = inst.get_coverage_report()
    print(report)

# Dynamic tracing with LLDB
with BinaryInstrumentor('/path/to/binary', use_lldb=True) as inst:
    # Trace function execution
    trace = inst.trace_function('main')
    
    # Export coverage
    inst.export_coverage('coverage.json')
```

### rex.binary_analysis.InMemoryFuzzer

High-performance in-memory fuzzer.

**Usage:**
```python
from rex.binary_analysis import InMemoryFuzzer

# Create fuzzer
fuzzer = InMemoryFuzzer('/path/to/binary', 'target_function')

# Add seed inputs
fuzzer.add_seed(b'test input')
fuzzer.add_seed(b'another seed')
fuzzer.add_seeds_from_directory('./seeds')

# Fuzz for 60 seconds
fuzzer.fuzz(duration=60)

# Or fuzz for specific iterations
fuzzer.fuzz(iterations=10000)

# Save results
fuzzer.save_crashes('./crashes')
fuzzer.save_corpus('./corpus')
```

**Mutation Strategies:**
- Bit flipping
- Byte flipping
- Arithmetic operations
- Interesting values (edge cases)
- Insertion/deletion
- Splicing

## Installation Requirements

### Required Dependencies

```bash
# Python dependencies
pip install r2pipe

# Radare2
# Ubuntu/Debian:
apt-get install radare2

# macOS:
brew install radare2

# From source:
git clone https://github.com/radare/radare2
cd radare2
./sys/install.sh

# LLDB (optional, for dynamic debugging)
# Ubuntu/Debian:
apt-get install lldb python3-lldb

# macOS:
xcode-select --install

# Or via Homebrew:
brew install llvm
```

## Use Cases

### 1. Interactive Binary Analysis

Use r2gdb for familiar GDB-like interaction with binaries:

```bash
# Analyze a suspicious binary
python3 tools/binary_analysis/r2gdb.py suspicious_binary

# In the debugger:
(r2gdb) info functions    # List all functions
(r2gdb) strings 10        # Find strings
(r2gdb) imports           # Check imports
(r2gdb) xrefs to main     # Find xrefs to main
```

### 2. Code Coverage Analysis

Track which code paths are executed:

```python
from rex.binary_analysis import BinaryInstrumentor

with BinaryInstrumentor('target', use_lldb=True) as inst:
    # Instrument all functions
    functions = inst.find_interesting_functions()
    for func in functions:
        inst.instrument_function(hex(func['offset']))
    
    # Run and collect coverage
    trace = inst.trace_execution(max_steps=10000)
    
    # Export for analysis
    inst.export_coverage('coverage_report.json')
```

### 3. Vulnerability Discovery

Use the fuzzer to find crashes:

```python
from rex.binary_analysis import InMemoryFuzzer

# Target a parsing function
fuzzer = InMemoryFuzzer('./parser', 'parse_input')

# Add initial seeds
fuzzer.add_seeds_from_directory('./test_cases')

# Fuzz aggressively
fuzzer.fuzz(iterations=100000)

# Review crashes
print(f"Found {len(fuzzer.crashes)} crashes")
fuzzer.save_crashes('./crash_analysis')
```

### 4. Exploit Development

Analyze and manipulate program execution:

```python
from rex.binary_analysis import LLDBDebugger

with LLDBDebugger('./vulnerable_app') as dbg:
    # Find vulnerable function
    dbg.set_breakpoint('vulnerable_function')
    dbg.continue_exec()
    
    # Examine state
    regs = dbg.get_registers()
    rsp = regs['rsp']
    
    # Read stack
    stack = dbg.read_memory(rsp, 256)
    
    # Manipulate for ROP chain testing
    dbg.write_memory(rsp, b'\x41' * 8)
    dbg.continue_exec()
```

## Advanced Features

### Stack Manipulation for Fast Fuzzing

The fuzzer can manipulate the stack pointer to rapidly test functions:

1. Set breakpoint at target function
2. Let program reach function naturally once
3. Save stack state
4. For each fuzzing iteration:
   - Restore stack pointer
   - Inject mutated input
   - Execute function
   - Check for crashes/new coverage

This is much faster than restarting the process each time.

### Coverage-Guided Fuzzing

The fuzzer tracks code coverage and prioritizes inputs that discover new paths:

- AFL-style edge coverage
- Basic block tracking
- Coverage bitmap with 64KB size
- Automatic corpus minimization

### Integration with Metasploit

These tools integrate with Metasploit post-exploitation modules:

```ruby
# In a Meterpreter session
execute_script('binary_analysis/analyze_binary.rb', binary_path)
```

## Performance Tips

1. **Use static analysis first** - Radare2 wrapper is faster for initial reconnaissance
2. **LLDB for dynamic** - Only use LLDB when you need runtime information
3. **Limit trace length** - Set reasonable max_steps to avoid hanging
4. **Corpus management** - Keep corpus small and diverse
5. **Parallel fuzzing** - Run multiple fuzzer instances

## Security Considerations

- Run untrusted binaries in sandboxed environments
- Be cautious with LLDB/debugging features on production systems
- Fuzzing can trigger unexpected behavior (crashes, resource exhaustion)
- Always validate results before taking action

## Troubleshooting

### r2pipe not found
```bash
pip install r2pipe
```

### LLDB Python bindings not available
```bash
# Ubuntu/Debian
apt-get install python3-lldb

# Or use system Python with LLDB
/usr/bin/python3 -c "import lldb; print(lldb.__file__)"
```

### Radare2 analysis hanging
- Try without `-2` debug flag
- Reduce analysis depth: `aaa` → `aa`
- Use smaller binaries for testing

### Fuzzer not finding crashes
- Increase iterations or duration
- Improve seed corpus quality
- Check if instrumentation is working
- Verify target function is reachable

## Contributing

When adding new features:

1. Follow existing code style
2. Add docstrings to all functions
3. Include usage examples
4. Update this README
5. Test with multiple binary formats

## References

- [Radare2 Book](https://book.rada.re/)
- [LLDB Documentation](https://lldb.llvm.org/)
- [AFL Fuzzer](https://github.com/google/AFL)
- [libFuzzer](https://llvm.org/docs/LibFuzzer.html)
- [GDB Quick Reference](https://sourceware.org/gdb/current/onlinedocs/gdb)
