#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
Example: Using LLVM/libfuzzrt Integration

This example demonstrates how to use the LLVM instrumentation module
to instrument binaries with sanitizers for vulnerability discovery.
"""

import sys
import os
import tempfile

# Add lib to path
lib_path = os.path.abspath(os.path.join(os.path.dirname(__file__), '..', 'lib'))
sys.path.insert(0, lib_path)

import importlib.util
spec = importlib.util.spec_from_file_location(
    "llvm_instrumentation",
    os.path.join(lib_path, 'msf', 'util', 'llvm_instrumentation.py')
)
llvm_instrumentation = importlib.util.module_from_spec(spec)
spec.loader.exec_module(llvm_instrumentation)

# Import classes
BinaryInstrumentor = llvm_instrumentation.BinaryInstrumentor


def main():
    """Run demonstration"""
    print("\n")
    print("*" * 70)
    print("*" + "  LLVM/libfuzzrt Instrumentation Demo".center(68) + "*")
    print("*" * 70)
    print("\nThis demo shows how to instrument binaries with ASAN.\n")
    
    print("[*] Creating a simple test program...")
    
    # Create a simple test
    test_code = '''
#include <stdio.h>
#include <stdlib.h>

int main() {
    printf("Hello from test program\\n");
    return 0;
}
'''
    
    # Write to temporary file
    with tempfile.NamedTemporaryFile(mode='w', suffix='.c', delete=False) as f:
        f.write(test_code)
        source_file = f.name
    
    try:
        print(f"[*] Source file: {source_file}")
        
        # Instrument with ASAN
        output_file = source_file.replace('.c', '_asan')
        instrumentor = BinaryInstrumentor(verbose=True)
        
        print("\n[*] Instrumenting with ASAN...")
        success = instrumentor.instrument_with_asan(
            source_file,
            output_file,
            use_frida=False
        )
        
        if success:
            print(f"\n[+] Successfully instrumented: {output_file}")
            print(f"\n[*] Test the instrumented binary:")
            print(f"    {output_file}")
        else:
            print("\n[!] Instrumentation failed")
            print("[*] Make sure LLVM/Clang is installed:")
            print("    sudo apt-get install clang llvm")
            
    finally:
        # Clean up
        if os.path.exists(source_file):
            os.unlink(source_file)
    
    print("\n" + "=" * 70)
    print("Demo complete!")
    print("=" * 70 + "\n")
    
    return 0


if __name__ == '__main__':
    sys.exit(main())
