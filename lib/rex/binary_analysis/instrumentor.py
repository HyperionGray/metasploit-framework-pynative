"""
Binary Instrumentation for Coverage Tracking

Provides instrumentation capabilities for tracking code coverage,
similar to AFL, LLVM SanitizerCoverage, and other coverage tools.
"""

import os
import struct
from typing import Set, Dict, List, Optional, Tuple, Any
from collections import defaultdict
import hashlib


class CoverageMap:
    """
    Coverage map for tracking executed basic blocks.
    
    Similar to AFL's coverage bitmap, this tracks which code paths
    have been executed during fuzzing or analysis.
    """
    
    def __init__(self, size: int = 65536):
        """
        Initialize coverage map.
        
        Args:
            size: Size of coverage bitmap (default 64KB like AFL)
        """
        self.size = size
        self.bitmap = bytearray(size)
        self.edges = {}  # (src, dst) -> hit_count
        self.blocks = set()  # Set of hit basic block addresses
        self.virgin_bits = bytearray([255] * size)  # Track new coverage
    
    def record_edge(self, src: int, dst: int):
        """
        Record execution of an edge (basic block transition).
        
        Args:
            src: Source address
            dst: Destination address
        """
        # AFL-style edge hashing
        edge_hash = ((src >> 1) ^ dst) % self.size
        self.bitmap[edge_hash] = min(255, self.bitmap[edge_hash] + 1)
        
        # Track edge hit count
        edge = (src, dst)
        self.edges[edge] = self.edges.get(edge, 0) + 1
    
    def record_block(self, address: int):
        """
        Record execution of a basic block.
        
        Args:
            address: Block address
        """
        self.blocks.add(address)
    
    def has_new_coverage(self) -> bool:
        """
        Check if new coverage was discovered.
        
        Returns:
            True if new edges were covered
        """
        for i in range(self.size):
            if self.bitmap[i] != 0 and self.virgin_bits[i] != 0:
                self.virgin_bits[i] = 0
                return True
        return False
    
    def get_coverage_hash(self) -> str:
        """
        Get hash of current coverage state.
        
        Returns:
            SHA256 hash of coverage bitmap
        """
        return hashlib.sha256(bytes(self.bitmap)).hexdigest()
    
    def reset(self):
        """Reset coverage map"""
        self.bitmap = bytearray(self.size)
        self.edges.clear()
        self.blocks.clear()
    
    def get_stats(self) -> Dict[str, Any]:
        """Get coverage statistics"""
        return {
            'blocks_hit': len(self.blocks),
            'edges_hit': len(self.edges),
            'total_edge_hits': sum(self.edges.values()),
            'bitmap_density': sum(1 for b in self.bitmap if b > 0) / self.size,
        }


class BinaryInstrumentor:
    """
    Binary instrumentation for coverage-guided fuzzing.
    
    Supports:
    - Static instrumentation via Radare2
    - Dynamic instrumentation via LLDB
    - Coverage tracking
    - Function tracing
    """
    
    def __init__(self, binary_path: str, use_lldb: bool = False):
        """
        Initialize instrumentor.
        
        Args:
            binary_path: Path to binary to instrument
            use_lldb: Use LLDB for dynamic instrumentation
        """
        self.binary_path = binary_path
        self.use_lldb = use_lldb
        self.coverage_map = CoverageMap()
        self.trace_log = []
        self.function_hits = defaultdict(int)
        
        # Instrumentation state
        self.instrumented_functions = set()
        self.instrumentation_points = []
        
        if use_lldb:
            from .lldb_debugger import LLDBDebugger
            self.debugger = LLDBDebugger(binary_path)
        else:
            from .radare2_wrapper import Radare2Wrapper
            self.analyzer = Radare2Wrapper(binary_path)
    
    def __enter__(self):
        if self.use_lldb:
            self.debugger.start()
        return self
    
    def __exit__(self, exc_type, exc_val, exc_tb):
        if self.use_lldb and hasattr(self, 'debugger'):
            self.debugger.stop()
        elif hasattr(self, 'analyzer'):
            self.analyzer.close()
    
    # Static analysis and instrumentation
    
    def analyze_control_flow(self, function_address: str) -> Dict[str, Any]:
        """
        Analyze control flow graph of a function.
        
        Args:
            function_address: Function address to analyze
            
        Returns:
            Control flow information
        """
        if self.use_lldb:
            raise NotImplementedError("CFG analysis requires Radare2")
        
        # Get function info
        self.analyzer.analyze_function(function_address)
        
        # Get basic blocks
        cmd = f'agj @ {function_address}'
        cfg = self.analyzer.execute_command_json(cmd)
        
        if not cfg or not isinstance(cfg, list) or len(cfg) == 0:
            return {'blocks': [], 'edges': []}
        
        blocks = []
        edges = []
        
        # Parse CFG
        for node in cfg[0].get('blocks', []):
            block_info = {
                'address': node.get('offset'),
                'size': node.get('size'),
                'instructions': node.get('ninstr', 0),
            }
            blocks.append(block_info)
            
            # Get edges from this block
            if 'jump' in node:
                edges.append((node['offset'], node['jump']))
            if 'fail' in node:
                edges.append((node['offset'], node['fail']))
        
        return {
            'blocks': blocks,
            'edges': edges,
            'function': function_address,
        }
    
    def find_interesting_functions(self, patterns: Optional[List[str]] = None) -> List[Dict[str, Any]]:
        """
        Find interesting functions for instrumentation.
        
        Args:
            patterns: Optional list of name patterns to match
            
        Returns:
            List of interesting function info
        """
        if self.use_lldb:
            raise NotImplementedError("Function discovery requires Radare2")
        
        all_functions = self.analyzer.list_functions()
        
        if not patterns:
            # Default interesting patterns
            patterns = [
                'parse', 'read', 'write', 'handle', 'process',
                'decode', 'encode', 'verify', 'validate'
            ]
        
        interesting = []
        for func in all_functions:
            name = func.get('name', '').lower()
            if any(pattern in name for pattern in patterns):
                interesting.append(func)
        
        return interesting
    
    def instrument_function(self, function_address: str) -> bool:
        """
        Set up instrumentation for a function.
        
        Args:
            function_address: Function to instrument
            
        Returns:
            True if successful
        """
        if function_address in self.instrumented_functions:
            return True
        
        if self.use_lldb:
            # Set breakpoint at function entry
            bp_id = self.debugger.set_breakpoint(function_address)
            self.instrumentation_points.append({
                'type': 'function_entry',
                'address': function_address,
                'breakpoint_id': bp_id,
            })
        else:
            # Analyze function CFG
            cfg = self.analyze_control_flow(function_address)
            
            # Record instrumentation points
            for block in cfg.get('blocks', []):
                self.instrumentation_points.append({
                    'type': 'basic_block',
                    'address': block['address'],
                    'size': block['size'],
                })
        
        self.instrumented_functions.add(function_address)
        return True
    
    def instrument_all_functions(self):
        """Instrument all functions in binary"""
        if self.use_lldb:
            raise NotImplementedError("Bulk instrumentation not supported with LLDB")
        
        functions = self.analyzer.list_functions()
        for func in functions:
            address = hex(func['offset'])
            try:
                self.instrument_function(address)
            except Exception as e:
                # Skip functions that fail to instrument
                pass
    
    # Dynamic tracing
    
    def trace_execution(self, max_steps: int = 10000) -> List[Dict[str, Any]]:
        """
        Trace program execution.
        
        Args:
            max_steps: Maximum number of instructions to trace
            
        Returns:
            List of trace entries
        """
        if not self.use_lldb:
            raise NotImplementedError("Tracing requires LLDB")
        
        trace = []
        prev_pc = None
        
        for _ in range(max_steps):
            # Get current PC
            registers = self.debugger.get_registers()
            pc = registers.get('rip') or registers.get('pc') or registers.get('eip')
            
            if pc is None:
                break
            
            # Record edge if we have previous PC
            if prev_pc is not None:
                self.coverage_map.record_edge(prev_pc, pc)
            
            self.coverage_map.record_block(pc)
            
            # Get instruction info
            trace_entry = {
                'pc': pc,
                'instruction': None,  # Could disassemble here
            }
            trace.append(trace_entry)
            
            # Step one instruction
            result = self.debugger.step_instruction()
            
            # Check if process stopped unexpectedly
            if 'Signal' in result or 'Exception' in result:
                break
            
            prev_pc = pc
        
        self.trace_log.extend(trace)
        return trace
    
    def trace_function(self, function_address: str) -> List[Dict[str, Any]]:
        """
        Trace execution of a specific function.
        
        Args:
            function_address: Function to trace
            
        Returns:
            Trace of function execution
        """
        if not self.use_lldb:
            raise NotImplementedError("Function tracing requires LLDB")
        
        # Set breakpoint at function
        bp_id = self.debugger.set_breakpoint(function_address)
        
        # Run to breakpoint
        self.debugger.continue_exec()
        
        # Trace until function returns
        trace = []
        depth = 1
        
        while depth > 0:
            registers = self.debugger.get_registers()
            pc = registers.get('rip') or registers.get('pc') or registers.get('eip')
            
            trace.append({'pc': pc})
            
            # Step and check if we're returning
            result = self.debugger.step_instruction()
            
            # Simple depth tracking (not perfect, but works for basic cases)
            # This should be improved with proper call/ret detection
            if depth > 100:  # Safety limit
                break
            
            depth -= 1  # Simplified
        
        # Clean up breakpoint
        self.debugger.delete_breakpoint(bp_id)
        
        self.function_hits[function_address] += 1
        return trace
    
    # Coverage analysis
    
    def get_coverage_report(self) -> Dict[str, Any]:
        """
        Get comprehensive coverage report.
        
        Returns:
            Coverage statistics and details
        """
        stats = self.coverage_map.get_stats()
        
        report = {
            'coverage': stats,
            'instrumented_functions': len(self.instrumented_functions),
            'instrumentation_points': len(self.instrumentation_points),
            'function_hits': dict(self.function_hits),
            'trace_length': len(self.trace_log),
        }
        
        return report
    
    def export_coverage(self, output_path: str):
        """
        Export coverage data to file.
        
        Args:
            output_path: Path to write coverage data
        """
        import json
        
        report = self.get_coverage_report()
        
        # Add detailed coverage info
        report['blocks'] = list(self.coverage_map.blocks)
        report['edges'] = [
            {'src': src, 'dst': dst, 'hits': count}
            for (src, dst), count in self.coverage_map.edges.items()
        ]
        
        with open(output_path, 'w') as f:
            json.dump(report, f, indent=2)
    
    def compare_coverage(self, other: 'BinaryInstrumentor') -> Dict[str, Any]:
        """
        Compare coverage with another instrumentation session.
        
        Args:
            other: Another BinaryInstrumentor instance
            
        Returns:
            Coverage comparison
        """
        my_blocks = self.coverage_map.blocks
        other_blocks = other.coverage_map.blocks
        
        my_edges = set(self.coverage_map.edges.keys())
        other_edges = set(other.coverage_map.edges.keys())
        
        return {
            'unique_blocks': len(my_blocks - other_blocks),
            'common_blocks': len(my_blocks & other_blocks),
            'unique_edges': len(my_edges - other_edges),
            'common_edges': len(my_edges & other_edges),
        }


def main():
    """Example usage"""
    import sys
    
    if len(sys.argv) < 2:
        print("Usage: python instrumentor.py <binary_path>")
        sys.exit(1)
    
    binary = sys.argv[1]
    
    print(f"Instrumenting {binary}...")
    
    # Static analysis example
    print("\n=== Static Analysis ===")
    with BinaryInstrumentor(binary, use_lldb=False) as inst:
        # Find interesting functions
        interesting = inst.find_interesting_functions()
        print(f"Found {len(interesting)} interesting functions")
        
        if interesting:
            func = interesting[0]
            print(f"\nAnalyzing: {func.get('name')} @ {hex(func.get('offset', 0))}")
            
            # Analyze control flow
            cfg = inst.analyze_control_flow(hex(func['offset']))
            print(f"  Basic blocks: {len(cfg['blocks'])}")
            print(f"  Edges: {len(cfg['edges'])}")
    
    print("\nInstrumentation complete!")


if __name__ == '__main__':
    main()
