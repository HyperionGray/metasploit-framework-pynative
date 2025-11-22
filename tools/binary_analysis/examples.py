#!/usr/bin/env python3
"""
Binary Analysis Examples

Demonstrates usage of the binary analysis tools.
"""

import sys
import os

# Add lib to path
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', '..', 'lib'))

from rex.binary_analysis import (
    Radare2Wrapper,
    LLDBDebugger,
    BinaryInstrumentor,
    InMemoryFuzzer
)


def example_radare2_analysis(binary_path):
    """Example: Static analysis with Radare2"""
    print("="*60)
    print("Example 1: Static Analysis with Radare2")
    print("="*60)
    
    with Radare2Wrapper(binary_path) as r2:
        # Get binary info
        print("\n1. Binary Information:")
        info = r2.get_binary_info()
        print(f"   Architecture: {info.get('bin', {}).get('arch')}")
        print(f"   Bits: {info.get('bin', {}).get('bits')}")
        print(f"   Entry point: {r2.get_entry_point()}")
        
        # List functions
        print("\n2. Functions:")
        functions = r2.list_functions()
        print(f"   Total functions: {len(functions)}")
        for func in functions[:5]:
            print(f"   - {func.get('name')} @ {hex(func.get('offset', 0))}")
        
        # Find strings
        print("\n3. Strings:")
        strings = r2.find_strings(min_length=10)
        print(f"   Total strings: {len(strings)}")
        for s in strings[:5]:
            print(f"   - {s.get('string', '')[:50]}")
        
        # Get imports
        print("\n4. Imports:")
        imports = r2.get_imports()
        print(f"   Total imports: {len(imports)}")
        for imp in imports[:5]:
            print(f"   - {imp.get('name')}")


def example_lldb_debugging(binary_path):
    """Example: Dynamic debugging with LLDB"""
    print("\n" + "="*60)
    print("Example 2: Dynamic Debugging with LLDB")
    print("="*60)
    
    try:
        with LLDBDebugger(binary_path) as dbg:
            print("\n1. Process started")
            info = dbg.get_process_info()
            print(f"   PID: {info['pid']}")
            print(f"   State: {info['state_name']}")
            
            # Set breakpoint at main
            print("\n2. Setting breakpoint at main...")
            try:
                bp_id = dbg.set_breakpoint('main')
                print(f"   Breakpoint {bp_id} set")
            except Exception as e:
                print(f"   Could not set breakpoint: {e}")
                return
            
            # Continue to breakpoint
            print("\n3. Running to breakpoint...")
            result = dbg.continue_exec()
            print(f"   Stop reason: {result}")
            
            # Show registers
            print("\n4. Register values:")
            regs = dbg.get_registers()
            for name in ['rip', 'rsp', 'rbp', 'rax', 'rbx', 'rcx', 'rdx']:
                if name in regs:
                    print(f"   {name}: 0x{regs[name]:x}")
            
            # Show backtrace
            print("\n5. Backtrace:")
            bt = dbg.get_backtrace()
            for frame in bt[:5]:
                print(f"   #{frame['index']}: {frame['function']} @ 0x{frame['pc']:x}")
    
    except ImportError as e:
        print(f"\n   LLDB not available: {e}")
        print("   Install with: pip install lldb-python")
    except Exception as e:
        print(f"\n   Error during debugging: {e}")


def example_instrumentation(binary_path):
    """Example: Binary instrumentation for coverage"""
    print("\n" + "="*60)
    print("Example 3: Binary Instrumentation")
    print("="*60)
    
    with BinaryInstrumentor(binary_path, use_lldb=False) as inst:
        # Find interesting functions
        print("\n1. Finding interesting functions...")
        interesting = inst.find_interesting_functions(['main', 'parse', 'handle'])
        print(f"   Found {len(interesting)} interesting functions")
        
        if interesting:
            func = interesting[0]
            print(f"\n2. Analyzing: {func.get('name')}")
            
            # Analyze control flow
            try:
                cfg = inst.analyze_control_flow(hex(func['offset']))
                print(f"   Basic blocks: {len(cfg['blocks'])}")
                print(f"   Edges: {len(cfg['edges'])}")
                
                if cfg['blocks']:
                    print("\n3. First 3 basic blocks:")
                    for block in cfg['blocks'][:3]:
                        print(f"   - Address: {hex(block['address'])}, "
                              f"Size: {block['size']}, "
                              f"Instructions: {block['instructions']}")
            except Exception as e:
                print(f"   Could not analyze CFG: {e}")
        
        # Get coverage report
        print("\n4. Coverage report:")
        report = inst.get_coverage_report()
        print(f"   Instrumented functions: {report['instrumented_functions']}")
        print(f"   Instrumentation points: {report['instrumentation_points']}")


def example_fuzzing(binary_path):
    """Example: In-memory fuzzing (conceptual)"""
    print("\n" + "="*60)
    print("Example 4: In-Memory Fuzzing (Conceptual)")
    print("="*60)
    
    print("\n1. Creating fuzzer...")
    print(f"   Target binary: {binary_path}")
    print("   Target function: main")
    
    print("\n2. Fuzzer configuration:")
    print("   - Mutation strategies: bit_flip, byte_flip, arithmetic, interesting")
    print("   - Coverage tracking: AFL-style edge coverage")
    print("   - Corpus management: Energy-based selection")
    
    print("\n3. Example fuzzing workflow:")
    print("   a. Load seed inputs")
    print("   b. Select seed based on energy")
    print("   c. Mutate input")
    print("   d. Execute with instrumentation")
    print("   e. Track coverage and crashes")
    print("   f. Update corpus with interesting inputs")
    print("   g. Repeat")
    
    print("\n4. Typical results:")
    print("   - Iterations: 10,000+")
    print("   - Exec/sec: 100-1000+ (depending on target)")
    print("   - New coverage: Varies by target")
    print("   - Crashes: Saved to output directory")
    
    print("\nNote: Actual fuzzing requires LLDB and can be resource-intensive")


def main():
    """Run all examples"""
    if len(sys.argv) < 2:
        print("Binary Analysis Examples")
        print("\nUsage: python3 examples.py <binary_path>")
        print("\nExamples:")
        print("  python3 examples.py /bin/ls")
        print("  python3 examples.py /usr/bin/cat")
        sys.exit(1)
    
    binary = sys.argv[1]
    
    if not os.path.exists(binary):
        print(f"Error: Binary not found: {binary}")
        sys.exit(1)
    
    print(f"Binary Analysis Examples: {binary}\n")
    
    try:
        # Example 1: Static analysis
        example_radare2_analysis(binary)
        
        # Example 2: Dynamic debugging (may not work in all environments)
        # example_lldb_debugging(binary)
        
        # Example 3: Instrumentation
        example_instrumentation(binary)
        
        # Example 4: Fuzzing (conceptual overview)
        example_fuzzing(binary)
        
        print("\n" + "="*60)
        print("Examples completed successfully!")
        print("="*60)
        
    except KeyboardInterrupt:
        print("\n\nInterrupted by user")
    except Exception as e:
        print(f"\nError: {e}")
        import traceback
        traceback.print_exc()


if __name__ == '__main__':
    main()
