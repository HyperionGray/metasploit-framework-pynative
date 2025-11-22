# LLVM/libfuzzrt Binary Instrumentation Module

## Description

This module provides comprehensive binary instrumentation capabilities using LLVM-based sanitizers and Frida runtime instrumentation. It enables security researchers and penetration testers to instrument target binaries with memory safety checks, undefined behavior detection, and efficient code coverage tracking.

The module implements:
- **AddressSanitizer (ASAN)**: Fast memory error detector for use-after-free, buffer overflows, etc.
- **UndefinedBehaviorSanitizer (UBSan)**: Detection of undefined behavior in C/C++ code
- **ThreadSanitizer (TSan)**: Data race detection for multi-threaded programs
- **MemorySanitizer (MSan)**: Detector of uninitialized memory reads
- **LeakSanitizer (LSan)**: Memory leak detection
- **Efficient Edge Instrumentation**: Self-removing hooks for performance optimization

## Instrumentation Modes

### 1. LLVM Compile Mode
Recompiles source code with LLVM sanitizers. Requires source code or LLVM IR.

**Advantages:**
- Most comprehensive instrumentation
- Best performance
- Full sanitizer features

**Disadvantages:**
- Requires source code
- Requires LLVM/Clang toolchain

### 2. Frida Mode
Runtime instrumentation without recompilation using Frida dynamic instrumentation toolkit.

**Advantages:**
- No source code required
- Works on compiled binaries
- Dynamic and flexible

**Disadvantages:**
- Runtime overhead
- Limited compared to compile-time checks
- Requires Frida installation

### 3. Binary Patch Mode (Experimental)
Direct binary patching for instrumentation.

**Status:** Not yet fully implemented

## Efficient Edge Instrumentation

The module implements an innovative approach to code coverage tracking with **self-removing edge instrumentation**:

1. **Initial Instrumentation**: All function entries are hooked
2. **First Hit Detection**: When a function is called for the first time, it's logged
3. **Auto-Removal**: After logging, the hook is automatically removed
4. **Performance**: Dramatically reduces overhead after initial coverage pass

This approach is ideal for:
- Coverage-guided fuzzing
- One-time coverage analysis
- Performance-critical instrumentation

## Installation Requirements

### LLVM Mode
```bash
# Ubuntu/Debian
sudo apt-get install clang llvm

# macOS
brew install llvm

# Verify installation
clang --version
```

### Frida Mode
```bash
# Install Frida
pip3 install frida frida-tools

# Verify installation
frida --version
```

## Module Options

### INPUT_BINARY
**Required:** Yes  
**Type:** Path  
**Description:** Path to input binary or source file

For LLVM mode, this should be:
- C/C++ source file (.c, .cpp)
- LLVM IR file (.ll)
- LLVM bitcode file (.bc)

For Frida mode, this can be any binary executable.

### OUTPUT_PATH
**Required:** Yes  
**Type:** Path  
**Description:** Path for instrumented output

For LLVM mode: Path for the instrumented executable  
For Frida mode: Path for the Frida JavaScript instrumentation script

### MODE
**Required:** Yes  
**Type:** Enum [llvm, frida, patch]  
**Default:** frida  
**Description:** Instrumentation mode to use

### SANITIZERS
**Required:** No  
**Type:** String  
**Default:** asan  
**Description:** Comma-separated list of sanitizers

Valid values:
- `asan` - AddressSanitizer
- `ubsan` - UndefinedBehaviorSanitizer
- `msan` - MemorySanitizer
- `tsan` - ThreadSanitizer
- `lsan` - LeakSanitizer

Examples:
- `asan`
- `asan,ubsan`
- `asan,ubsan,lsan`

### EDGE_INSTRUMENTATION
**Required:** Yes  
**Type:** Boolean  
**Default:** true  
**Description:** Enable efficient edge instrumentation with auto-removal

When enabled (recommended), instrumentation hooks are automatically removed after first hit for better performance.

### VERBOSE
**Required:** No  
**Type:** Boolean  
**Default:** false  
**Description:** Enable verbose output for debugging

## Usage Examples

### Example 1: Basic ASAN Instrumentation

```
msf6 > use auxiliary/fuzzers/binary/llvm_instrumentation
msf6 auxiliary(fuzzers/binary/llvm_instrumentation) > set INPUT_BINARY /tmp/vulnerable.c
msf6 auxiliary(fuzzers/binary/llvm_instrumentation) > set OUTPUT_PATH /tmp/vulnerable_asan
msf6 auxiliary(fuzzers/binary/llvm_instrumentation) > set MODE llvm
msf6 auxiliary(fuzzers/binary/llvm_instrumentation) > set SANITIZERS asan
msf6 auxiliary(fuzzers/binary/llvm_instrumentation) > run

[*] Starting LLVM/libfuzzrt binary instrumentation
[*] Running: python3 /path/to/llvm_instrumentation.py /tmp/vulnerable.c -o /tmp/vulnerable_asan -m llvm -s asan
[+] Instrumentation successful!
[+] Output: /tmp/vulnerable_asan
[*] Sanitizer runtime options:
[*]   ASAN_OPTIONS='detect_leaks=1:detect_stack_use_after_return=1:check_initialization_order=1:strict_init_order=1:detect_invalid_pointer_pairs=2'
[*] Edge instrumentation: ENABLED
[*]   Hooks will auto-remove after first hit for efficiency
```

### Example 2: Multiple Sanitizers

```
msf6 auxiliary(fuzzers/binary/llvm_instrumentation) > set SANITIZERS asan,ubsan,lsan
msf6 auxiliary(fuzzers/binary/llvm_instrumentation) > set VERBOSE true
msf6 auxiliary(fuzzers/binary/llvm_instrumentation) > run

[*] Starting LLVM/libfuzzrt binary instrumentation
[*] Found clang: /usr/bin/clang
[*] Running: python3 /path/to/llvm_instrumentation.py /tmp/vulnerable.c -o /tmp/vulnerable_multi -m llvm -s asan -s ubsan -s lsan -v
[*] Compiling with: /usr/bin/clang /tmp/vulnerable.c -o /tmp/vulnerable_multi -fsanitize=address -fsanitize=undefined -fsanitize=leak -fno-omit-frame-pointer -g -O1
[+] Instrumentation successful!
[+] Output: /tmp/vulnerable_multi
[*] Sanitizer runtime options:
[*]   ASAN_OPTIONS='detect_leaks=1:detect_stack_use_after_return=1:check_initialization_order=1:strict_init_order=1:detect_invalid_pointer_pairs=2'
```

### Example 3: Frida Runtime Instrumentation

```
msf6 auxiliary(fuzzers/binary/llvm_instrumentation) > set INPUT_BINARY /bin/target_binary
msf6 auxiliary(fuzzers/binary/llvm_instrumentation) > set OUTPUT_PATH /tmp/frida_script.js
msf6 auxiliary(fuzzers/binary/llvm_instrumentation) > set MODE frida
msf6 auxiliary(fuzzers/binary/llvm_instrumentation) > set SANITIZERS asan,ubsan
msf6 auxiliary(fuzzers/binary/llvm_instrumentation) > run

[*] Starting LLVM/libfuzzrt binary instrumentation
[*] Running: python3 /path/to/llvm_instrumentation.py /bin/target_binary -o /tmp/frida_script.js -m frida -s asan -s ubsan
[+] Instrumentation successful!
[+] Output: /tmp/frida_script.js
[*] To use the Frida script:
[*]   frida -l /tmp/frida_script.js -f /path/to/target
[*]   or
[*]   frida -l /tmp/frida_script.js -n target_process
[*] Edge instrumentation: ENABLED
[*]   Hooks will auto-remove after first hit for efficiency
```

Then use the generated Frida script:
```bash
# Spawn new process with instrumentation
frida -l /tmp/frida_script.js -f /bin/target_binary

# Attach to running process
frida -l /tmp/frida_script.js -n target_binary
```

### Example 4: Fuzzing Integration

The instrumented binary can be used with fuzzing tools:

```bash
# Using AFL++
AFL_USE_ASAN=1 afl-fuzz -i input_dir -o output_dir -- /tmp/vulnerable_asan @@

# Using libFuzzer
/tmp/vulnerable_asan -max_len=1024 -timeout=1 corpus/

# Manual testing with ASAN
ASAN_OPTIONS='halt_on_error=0:log_path=/tmp/asan.log' /tmp/vulnerable_asan < test_input
```

## Common Use Cases

### 1. Vulnerability Research
Instrument target binaries to discover memory corruption vulnerabilities:
```
set INPUT_BINARY /path/to/target.c
set OUTPUT_PATH /tmp/target_instrumented
set SANITIZERS asan,ubsan
set MODE llvm
run
```

### 2. Exploit Development
Validate exploit reliability with sanitizer checks:
```
set INPUT_BINARY /path/to/vulnerable_service
set OUTPUT_PATH /tmp/frida_checks.js
set MODE frida
set SANITIZERS asan
run
```

### 3. Code Coverage Analysis
Track code coverage during security testing:
```
set EDGE_INSTRUMENTATION true
set MODE frida
run
```

### 4. Fuzzing Campaign
Prepare binaries for fuzzing with comprehensive checks:
```
set SANITIZERS asan,ubsan,lsan
set MODE llvm
run
```

## Troubleshooting

### Issue: "LLVM/Clang not found in PATH"
**Solution:** Install LLVM/Clang:
```bash
# Ubuntu/Debian
sudo apt-get install clang llvm

# Verify
which clang
```

### Issue: "Frida not available"
**Solution:** Install Frida:
```bash
pip3 install frida frida-tools
python3 -c "import frida; print(frida.__version__)"
```

### Issue: Compilation errors with sanitizers
**Solution:** Some code may not be compatible with all sanitizers. Try:
1. Use only ASAN: `set SANITIZERS asan`
2. Add compiler flags: Check the source for incompatibilities
3. Use Frida mode instead: `set MODE frida`

### Issue: High runtime overhead with Frida
**Solution:**
1. Ensure edge instrumentation is enabled: `set EDGE_INSTRUMENTATION true`
2. Reduce sanitizer count: Use only necessary sanitizers
3. Consider LLVM mode for production fuzzing

## Performance Considerations

### LLVM Mode
- **Overhead:** 2-5x for ASAN, 2-4x for UBSan
- **Best for:** Long-running fuzzing campaigns
- **Optimization:** Compile with `-O1` or `-O2`

### Frida Mode
- **Initial overhead:** High (10-100x)
- **After edge removal:** Moderate (2-10x)
- **Best for:** Quick analysis, closed-source binaries
- **Optimization:** Enable edge auto-removal

## Security Notes

### ASAN Environment Variables
The module sets secure ASAN defaults. To customize:
```bash
export ASAN_OPTIONS='detect_leaks=1:halt_on_error=0:log_path=/tmp/asan.log'
/tmp/instrumented_binary
```

### Frida Permissions
Frida requires appropriate permissions to attach to processes:
```bash
# May require sudo for some processes
sudo frida -l script.js -n target_process

# Or adjust ptrace_scope on Linux
echo 0 | sudo tee /proc/sys/kernel/yama/ptrace_scope
```

## References

- [AddressSanitizer Documentation](https://clang.llvm.org/docs/AddressSanitizer.html)
- [UndefinedBehaviorSanitizer](https://clang.llvm.org/docs/UndefinedBehaviorSanitizer.html)
- [Frida Documentation](https://frida.re/docs/home/)
- [LibFuzzer](https://llvm.org/docs/LibFuzzer.html)
- [AFL++](https://github.com/AFLplusplus/AFLplusplus)

## See Also

- `modules/auxiliary/fuzzers/http/*` - HTTP protocol fuzzers
- `modules/auxiliary/fuzzers/smtp/*` - SMTP protocol fuzzers
- `modules/exploits/linux/local/asan_suid_executable_priv_esc` - ASAN exploitation
