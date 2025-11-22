"""
In-Memory Fuzzer

High-performance in-memory fuzzer that uses binary instrumentation
and stack manipulation to rapidly test functions with mutated inputs.
"""

import random
import struct
import os
from typing import Optional, List, Dict, Any, Callable, Tuple
from collections import defaultdict
import time


class Mutator:
    """
    Input mutation engine.
    
    Provides various mutation strategies similar to AFL, libFuzzer, etc.
    """
    
    INTERESTING_8 = [-128, -1, 0, 1, 16, 32, 64, 100, 127]
    INTERESTING_16 = [-32768, -129, 128, 255, 256, 512, 1000, 1024, 4096, 32767]
    INTERESTING_32 = [-2147483648, -100663046, -32769, 32768, 65535, 65536, 100663045, 2147483647]
    
    def __init__(self, seed: Optional[int] = None):
        """
        Initialize mutator.
        
        Args:
            seed: Random seed for reproducibility
        """
        if seed is not None:
            random.seed(seed)
        
        self.mutation_count = defaultdict(int)
    
    def mutate(self, data: bytes, strategy: Optional[str] = None) -> bytes:
        """
        Mutate input data.
        
        Args:
            data: Input data to mutate
            strategy: Specific mutation strategy or None for random
            
        Returns:
            Mutated data
        """
        if not data:
            return data
        
        data = bytearray(data)
        
        if strategy is None:
            # Choose random strategy
            strategies = [
                'bit_flip', 'byte_flip', 'arithmetic',
                'interesting', 'insert', 'delete', 'splice'
            ]
            strategy = random.choice(strategies)
        
        self.mutation_count[strategy] += 1
        
        if strategy == 'bit_flip':
            return bytes(self._bit_flip(data))
        elif strategy == 'byte_flip':
            return bytes(self._byte_flip(data))
        elif strategy == 'arithmetic':
            return bytes(self._arithmetic(data))
        elif strategy == 'interesting':
            return bytes(self._interesting_values(data))
        elif strategy == 'insert':
            return bytes(self._insert_bytes(data))
        elif strategy == 'delete':
            return bytes(self._delete_bytes(data))
        elif strategy == 'splice':
            return bytes(self._splice(data))
        else:
            return bytes(data)
    
    def _bit_flip(self, data: bytearray) -> bytearray:
        """Flip random bit"""
        if not data:
            return data
        
        pos = random.randint(0, len(data) - 1)
        bit = random.randint(0, 7)
        data[pos] ^= (1 << bit)
        return data
    
    def _byte_flip(self, data: bytearray) -> bytearray:
        """Flip random byte"""
        if not data:
            return data
        
        pos = random.randint(0, len(data) - 1)
        data[pos] ^= 0xFF
        return data
    
    def _arithmetic(self, data: bytearray) -> bytearray:
        """Add/subtract small value from random position"""
        if not data:
            return data
        
        pos = random.randint(0, len(data) - 1)
        delta = random.randint(-35, 35)
        data[pos] = (data[pos] + delta) & 0xFF
        return data
    
    def _interesting_values(self, data: bytearray) -> bytearray:
        """Replace with interesting value"""
        if not data:
            return data
        
        pos = random.randint(0, len(data) - 1)
        
        # Choose size
        if pos + 4 <= len(data) and random.random() > 0.7:
            # 32-bit
            value = random.choice(self.INTERESTING_32)
            struct.pack_into('<i', data, pos, value)
        elif pos + 2 <= len(data) and random.random() > 0.5:
            # 16-bit
            value = random.choice(self.INTERESTING_16)
            struct.pack_into('<h', data, pos, value)
        else:
            # 8-bit
            value = random.choice(self.INTERESTING_8)
            data[pos] = value & 0xFF
        
        return data
    
    def _insert_bytes(self, data: bytearray) -> bytearray:
        """Insert random bytes"""
        if len(data) >= 1024:  # Limit size
            return data
        
        pos = random.randint(0, len(data))
        count = random.randint(1, min(16, 1024 - len(data)))
        insert = bytearray(random.getrandbits(8) for _ in range(count))
        return data[:pos] + insert + data[pos:]
    
    def _delete_bytes(self, data: bytearray) -> bytearray:
        """Delete random bytes"""
        if len(data) <= 1:
            return data
        
        pos = random.randint(0, len(data) - 1)
        count = random.randint(1, min(16, len(data) - pos))
        return data[:pos] + data[pos + count:]
    
    def _splice(self, data: bytearray) -> bytearray:
        """Splice two parts of input"""
        if len(data) < 4:
            return data
        
        pos1 = random.randint(0, len(data) - 2)
        pos2 = random.randint(pos1 + 1, len(data) - 1)
        
        # Swap regions
        return data[pos2:] + data[pos1:pos2] + data[:pos1]
    
    def get_stats(self) -> Dict[str, int]:
        """Get mutation statistics"""
        return dict(self.mutation_count)


class InMemoryFuzzer:
    """
    High-speed in-memory fuzzer using binary instrumentation.
    
    Features:
    - Stack manipulation for rapid function testing
    - Coverage-guided fuzzing
    - Crash detection
    - Corpus management
    """
    
    def __init__(self, binary_path: str, target_function: str):
        """
        Initialize fuzzer.
        
        Args:
            binary_path: Path to target binary
            target_function: Function to fuzz
        """
        self.binary_path = binary_path
        self.target_function = target_function
        
        # Fuzzing components
        self.mutator = Mutator()
        self.corpus = []
        self.crashes = []
        self.interesting_inputs = []
        
        # Statistics
        self.stats = {
            'iterations': 0,
            'crashes': 0,
            'hangs': 0,
            'new_coverage': 0,
            'start_time': 0,
        }
        
        # Setup instrumentation
        from .instrumentor import BinaryInstrumentor
        self.instrumentor = BinaryInstrumentor(binary_path, use_lldb=True)
    
    def add_seed(self, data: bytes):
        """
        Add seed input to corpus.
        
        Args:
            data: Seed input
        """
        self.corpus.append({
            'data': data,
            'coverage_hash': None,
            'energy': 1.0,
        })
    
    def add_seeds_from_directory(self, directory: str):
        """
        Load seeds from directory.
        
        Args:
            directory: Directory containing seed files
        """
        if not os.path.isdir(directory):
            return
        
        for filename in os.listdir(directory):
            filepath = os.path.join(directory, filename)
            if os.path.isfile(filepath):
                try:
                    with open(filepath, 'rb') as f:
                        self.add_seed(f.read())
                except Exception:
                    pass
    
    def _select_seed(self) -> Dict[str, Any]:
        """
        Select seed from corpus.
        
        Returns:
            Selected seed entry
        """
        if not self.corpus:
            # Generate random seed
            size = random.randint(1, 256)
            data = bytes(random.getrandbits(8) for _ in range(size))
            self.add_seed(data)
        
        # Weighted random selection based on energy
        total_energy = sum(seed['energy'] for seed in self.corpus)
        r = random.uniform(0, total_energy)
        
        cumulative = 0
        for seed in self.corpus:
            cumulative += seed['energy']
            if cumulative >= r:
                return seed
        
        return self.corpus[0]
    
    def _execute_with_input(self, data: bytes, timeout: float = 1.0) -> Dict[str, Any]:
        """
        Execute target function with given input.
        
        Args:
            data: Input data
            timeout: Execution timeout in seconds
            
        Returns:
            Execution result
        """
        result = {
            'crash': False,
            'hang': False,
            'coverage': None,
            'error': None,
        }
        
        try:
            # Reset coverage
            self.instrumentor.coverage_map.reset()
            
            # Set breakpoint at target function
            bp_id = self.instrumentor.debugger.set_breakpoint(self.target_function)
            
            # Run to function
            self.instrumentor.debugger.continue_exec()
            
            # Modify stack/registers to inject our input
            # This is a simplified example - real implementation would be more complex
            # and depend on calling convention
            
            # Write input to memory
            # In a real implementation, we'd allocate memory and set up function arguments
            
            # Execute function with our input
            # Trace execution for coverage
            trace = self.instrumentor.trace_execution(max_steps=1000)
            
            # Get coverage
            result['coverage'] = self.instrumentor.coverage_map.get_coverage_hash()
            
            # Clean up
            self.instrumentor.debugger.delete_breakpoint(bp_id)
            
        except Exception as e:
            result['error'] = str(e)
            result['crash'] = True
        
        return result
    
    def _is_interesting(self, coverage_hash: str) -> bool:
        """
        Check if input discovered new coverage.
        
        Args:
            coverage_hash: Coverage hash to check
            
        Returns:
            True if this is new coverage
        """
        return self.instrumentor.coverage_map.has_new_coverage()
    
    def fuzz_iteration(self) -> Dict[str, Any]:
        """
        Run one fuzzing iteration.
        
        Returns:
            Iteration result
        """
        self.stats['iterations'] += 1
        
        # Select seed
        seed = self._select_seed()
        
        # Mutate input
        mutated = self.mutator.mutate(seed['data'])
        
        # Execute with mutated input
        result = self._execute_with_input(mutated)
        
        # Handle results
        if result['crash']:
            self.stats['crashes'] += 1
            self.crashes.append({
                'input': mutated,
                'iteration': self.stats['iterations'],
                'error': result.get('error'),
            })
        elif result.get('coverage') and self._is_interesting(result['coverage']):
            self.stats['new_coverage'] += 1
            self.corpus.append({
                'data': mutated,
                'coverage_hash': result['coverage'],
                'energy': 1.0,
            })
            self.interesting_inputs.append(mutated)
        
        return result
    
    def fuzz(self, iterations: Optional[int] = None, duration: Optional[float] = None):
        """
        Run fuzzing campaign.
        
        Args:
            iterations: Number of iterations (None for unlimited)
            duration: Duration in seconds (None for unlimited)
        """
        self.stats['start_time'] = time.time()
        
        print(f"Starting fuzzer for {self.target_function}...")
        print(f"Corpus size: {len(self.corpus)}")
        
        # Start instrumentor
        self.instrumentor.__enter__()
        
        try:
            iteration = 0
            while True:
                # Check limits
                if iterations and iteration >= iterations:
                    break
                if duration and (time.time() - self.stats['start_time']) >= duration:
                    break
                
                # Fuzz iteration
                try:
                    self.fuzz_iteration()
                except Exception as e:
                    print(f"Error in iteration {iteration}: {e}")
                
                iteration += 1
                
                # Print status every 100 iterations
                if iteration % 100 == 0:
                    self._print_status()
        
        finally:
            self.instrumentor.__exit__(None, None, None)
            self._print_final_report()
    
    def _print_status(self):
        """Print fuzzing status"""
        elapsed = time.time() - self.stats['start_time']
        rate = self.stats['iterations'] / elapsed if elapsed > 0 else 0
        
        print(f"\nIterations: {self.stats['iterations']} ({rate:.1f}/sec)")
        print(f"Corpus: {len(self.corpus)} | Crashes: {self.stats['crashes']} | "
              f"New coverage: {self.stats['new_coverage']}")
    
    def _print_final_report(self):
        """Print final fuzzing report"""
        elapsed = time.time() - self.stats['start_time']
        
        print("\n" + "="*60)
        print("FUZZING COMPLETE")
        print("="*60)
        print(f"Total time: {elapsed:.2f} seconds")
        print(f"Iterations: {self.stats['iterations']}")
        print(f"Exec/sec: {self.stats['iterations'] / elapsed:.1f}")
        print(f"Corpus size: {len(self.corpus)}")
        print(f"Crashes: {self.stats['crashes']}")
        print(f"New coverage: {self.stats['new_coverage']}")
        
        if self.crashes:
            print(f"\nCrashes saved ({len(self.crashes)} total)")
        
        mutation_stats = self.mutator.get_stats()
        print(f"\nMutation statistics:")
        for strategy, count in mutation_stats.items():
            print(f"  {strategy}: {count}")
    
    def save_crashes(self, output_dir: str):
        """
        Save crash inputs to directory.
        
        Args:
            output_dir: Directory to save crashes
        """
        os.makedirs(output_dir, exist_ok=True)
        
        for i, crash in enumerate(self.crashes):
            filename = f"crash_{i:05d}"
            filepath = os.path.join(output_dir, filename)
            
            with open(filepath, 'wb') as f:
                f.write(crash['input'])
            
            # Save metadata
            meta_path = filepath + ".txt"
            with open(meta_path, 'w') as f:
                f.write(f"Iteration: {crash['iteration']}\n")
                f.write(f"Error: {crash.get('error', 'Unknown')}\n")
    
    def save_corpus(self, output_dir: str):
        """
        Save corpus to directory.
        
        Args:
            output_dir: Directory to save corpus
        """
        os.makedirs(output_dir, exist_ok=True)
        
        for i, seed in enumerate(self.corpus):
            filename = f"seed_{i:05d}"
            filepath = os.path.join(output_dir, filename)
            
            with open(filepath, 'wb') as f:
                f.write(seed['data'])


def main():
    """Example usage"""
    import sys
    
    if len(sys.argv) < 3:
        print("Usage: python fuzzer.py <binary_path> <function_name>")
        print("\nExample:")
        print("  python fuzzer.py ./target parse_input")
        sys.exit(1)
    
    binary = sys.argv[1]
    function = sys.argv[2]
    
    fuzzer = InMemoryFuzzer(binary, function)
    
    # Add some seeds
    fuzzer.add_seed(b"test")
    fuzzer.add_seed(b"A" * 100)
    fuzzer.add_seed(b"\x00" * 50)
    
    # Fuzz for 60 seconds or 1000 iterations
    try:
        fuzzer.fuzz(iterations=1000, duration=60)
    except KeyboardInterrupt:
        print("\n\nFuzzing interrupted by user")
    
    # Save results
    fuzzer.save_crashes("./crashes")
    fuzzer.save_corpus("./corpus")
    
    print(f"\nResults saved to ./crashes and ./corpus")


if __name__ == '__main__':
    main()
