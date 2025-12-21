# Metasploit Framework Examples

This directory contains example code demonstrating various features and integration patterns for the Metasploit Framework.

## Examples

### PF Task Example (`pf_task_example.py`)

Demonstrates how to write exploits as PF (Pwntools Framework) tasks instead of traditional MSF modules.

**Features:**
- Simple configuration via environment variables
- Multiple operation modes (analyze, fuzz, exploit, debug)
- Integration with pwntools for exploitation
- Integration with GDB for debugging
- Educational comments explaining each step

**Usage:**
```bash
# Analyze a binary
python3 pf_task_example.py --mode analyze --binary ./vulnerable

# Fuzz to find offset
export TARGET_HOST=192.168.1.100
export TARGET_PORT=9999
python3 pf_task_example.py --mode fuzz

# Run exploit
python3 pf_task_example.py --mode exploit --offset 256

# Debug with GDB
python3 pf_task_example.py --mode debug --binary ./vulnerable
```

**See Also:**
- [PF Integration Guide](../documentation/PF_INTEGRATION_GUIDE.md)
- [Exploit Writing Guide](../documentation/EXPLOIT_WRITING_GUIDE.md)

### LLVM Instrumentation Demo (`llvm_instrumentation_demo.py`)

Demonstrates binary instrumentation with LLVM sanitizers and Frida.

**Features:**
- Compile binaries with ASAN, UBSan, TSan, MSan, LSan
- Generate Frida instrumentation scripts
- Coverage-guided edge instrumentation
- Integration with AFL++, libFuzzer

**Usage:**
```bash
# Compile with ASAN
python3 llvm_instrumentation_demo.py

# See LLVM_INTEGRATION.md for comprehensive documentation
```

**See Also:**
- [LLVM Integration](../LLVM_INTEGRATION.md)
- [Binary Analysis Tools](../documentation/integrations/BINARY_ANALYSIS_TOOLS.md)

## Creating Your Own Examples

When creating examples:

1. **Make them educational** - Include comments explaining what's happening
2. **Keep them focused** - One concept per example
3. **Include documentation** - Usage instructions and expected output
4. **Test thoroughly** - Ensure examples work as documented
5. **Follow conventions** - Use consistent naming and structure

## Related Documentation

- [Exploit Writing Guide](../documentation/EXPLOIT_WRITING_GUIDE.md) - Comprehensive guide to writing exploits
- [PF Integration Guide](../documentation/PF_INTEGRATION_GUIDE.md) - How to use PF task system
- [Module Categorization](../documentation/MODULE_CATEGORIZATION.md) - Understanding legacy vs. active modules
- [Radare2 Quickstart](../RADARE2_QUICKSTART.md) - Using radare2 for binary analysis
- [Python Quickstart](../PYTHON_QUICKSTART.md) - Python integration basics

## Contributing Examples

To contribute new examples:

1. Create a well-commented script demonstrating a specific feature or pattern
2. Add documentation to this README
3. Test your example thoroughly
4. Submit a pull request

Good example topics:
- Specific exploitation techniques (ROP, heap exploitation, format strings, etc.)
- Tool integration patterns (radare2, ghidra, AFL++)
- Automation workflows
- Post-exploitation tasks
- Custom payload development
