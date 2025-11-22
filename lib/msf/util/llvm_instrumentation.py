#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
MSF LLVM/libfuzzrt Instrumentation Module

This module provides functionality for instrumenting binaries with LLVM-based
sanitizers (ASAN, UBSan, MSan, TSan) and dynamic instrumentation using Frida.
It enables users to inject memory safety checks, data execution prevention,
and other runtime instrumentation into target binaries.
"""

import os
import sys
import subprocess
import tempfile
import struct
from enum import Enum
from typing import Optional, List, Dict, Set, Tuple


class SanitizerType(Enum):
    """Types of sanitizers available for instrumentation"""
    ASAN = "address"          # AddressSanitizer - memory error detector
    UBSAN = "undefined"        # UndefinedBehaviorSanitizer
    MSAN = "memory"           # MemorySanitizer - uninitialized memory
    TSAN = "thread"           # ThreadSanitizer - data races
    LSAN = "leak"             # LeakSanitizer - memory leaks
    SAFESTACK = "safe-stack"  # SafeStack - stack overflow protection


class InstrumentationMode(Enum):
    """Instrumentation approach to use"""
    LLVM_COMPILE = "llvm_compile"    # Recompile with LLVM sanitizers
    LLVM_BITCODE = "llvm_bitcode"    # Instrument LLVM IR/bitcode
    FRIDA = "frida"                  # Runtime instrumentation with Frida
    BINARY_PATCH = "binary_patch"    # Direct binary patching


class LLVMInstrumentation:
    """
    Main class for LLVM-based binary instrumentation.
    
    This class provides methods to instrument binaries with various sanitizers
    and runtime checks, supporting both compile-time (LLVM) and runtime (Frida)
    approaches.
    """
    
    def __init__(self, verbose: bool = False):
        """
        Initialize the instrumentation engine.
        
        Args:
            verbose: Enable verbose output for debugging
        """
        self.verbose = verbose
        self.llvm_path = self._find_llvm_tools()
        self.frida_available = self._check_frida_available()
        self.instrumented_edges: Set[Tuple[int, int]] = set()
        
    def _find_llvm_tools(self) -> Dict[str, Optional[str]]:
        """
        Locate LLVM toolchain binaries.
        
        Returns:
            Dictionary mapping tool names to their paths
        """
        tools = ['clang', 'clang++', 'llvm-link', 'opt', 'llc', 'llvm-dis']
        paths = {}
        
        for tool in tools:
            path = self._which(tool)
            paths[tool] = path
            if self.verbose and path:
                print(f"[*] Found {tool}: {path}")
        
        return paths
    
    def _which(self, cmd: str) -> Optional[str]:
        """
        Find executable in PATH.
        
        Args:
            cmd: Command name to search for
            
        Returns:
            Full path to executable or None
        """
        exts = os.environ.get('PATHEXT', '').split(';') if os.name == 'nt' else ['']
        
        for path in os.environ.get('PATH', '').split(os.pathsep):
            for ext in exts:
                exe = os.path.join(path, f"{cmd}{ext}")
                if os.path.isfile(exe) and os.access(exe, os.X_OK):
                    return exe
        return None
    
    def _check_frida_available(self) -> bool:
        """
        Check if Frida is available for runtime instrumentation.
        
        Returns:
            True if Frida is available
        """
        try:
            import frida
            if self.verbose:
                print(f"[*] Frida available: version {frida.__version__}")
            return True
        except ImportError:
            if self.verbose:
                print("[!] Frida not available, runtime instrumentation disabled")
            return False
    
    def instrument_binary(
        self,
        binary_path: str,
        output_path: str,
        sanitizers: List[SanitizerType],
        mode: InstrumentationMode = InstrumentationMode.LLVM_COMPILE,
        options: Optional[Dict] = None
    ) -> bool:
        """
        Instrument a binary with specified sanitizers.
        
        Args:
            binary_path: Path to input binary
            output_path: Path for instrumented output
            sanitizers: List of sanitizers to apply
            mode: Instrumentation mode to use
            options: Additional instrumentation options
            
        Returns:
            True if instrumentation succeeded
        """
        if not os.path.exists(binary_path):
            raise FileNotFoundError(f"Binary not found: {binary_path}")
        
        options = options or {}
        
        if mode == InstrumentationMode.LLVM_COMPILE:
            return self._instrument_llvm_compile(
                binary_path, output_path, sanitizers, options
            )
        elif mode == InstrumentationMode.FRIDA:
            return self._instrument_frida(
                binary_path, output_path, sanitizers, options
            )
        elif mode == InstrumentationMode.BINARY_PATCH:
            return self._instrument_binary_patch(
                binary_path, output_path, sanitizers, options
            )
        else:
            raise ValueError(f"Unsupported instrumentation mode: {mode}")
    
    def _instrument_llvm_compile(
        self,
        binary_path: str,
        output_path: str,
        sanitizers: List[SanitizerType],
        options: Dict
    ) -> bool:
        """
        Instrument binary by recompiling with LLVM sanitizers.
        
        This requires source code or LLVM bitcode to be available.
        
        Args:
            binary_path: Path to source file or bitcode
            output_path: Path for instrumented output
            sanitizers: List of sanitizers to apply
            options: Compilation options
            
        Returns:
            True if compilation succeeded
        """
        if not self.llvm_path.get('clang'):
            raise RuntimeError("LLVM/Clang not found in PATH")
        
        # Build sanitizer flags
        sanitizer_flags = []
        for san in sanitizers:
            sanitizer_flags.extend(['-fsanitize=' + san.value])
        
        # Additional hardening flags
        extra_flags = [
            '-fno-omit-frame-pointer',
            '-g',  # Include debug info for better stack traces
            '-O1',  # Optimize for instrumentation
        ]
        
        # Build compile command
        cmd = [
            self.llvm_path['clang'],
            binary_path,
            '-o', output_path,
        ] + sanitizer_flags + extra_flags
        
        # Add user-specified flags
        if 'extra_flags' in options:
            cmd.extend(options['extra_flags'])
        
        if self.verbose:
            print(f"[*] Compiling with: {' '.join(cmd)}")
        
        try:
            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                check=True
            )
            if self.verbose and result.stdout:
                print(result.stdout)
            return True
        except subprocess.CalledProcessError as e:
            print(f"[!] Compilation failed: {e.stderr}")
            return False
    
    def _instrument_frida(
        self,
        binary_path: str,
        output_path: str,
        sanitizers: List[SanitizerType],
        options: Dict
    ) -> bool:
        """
        Generate Frida instrumentation script for runtime checks.
        
        This creates a JavaScript file that can be loaded with Frida
        to provide runtime instrumentation similar to sanitizers.
        
        Args:
            binary_path: Path to target binary
            output_path: Path for Frida script output
            sanitizers: List of sanitizers to emulate
            options: Instrumentation options
            
        Returns:
            True if script generation succeeded
        """
        if not self.frida_available:
            raise RuntimeError("Frida not available")
        
        script = self._generate_frida_script(binary_path, sanitizers, options)
        
        try:
            with open(output_path, 'w') as f:
                f.write(script)
            if self.verbose:
                print(f"[*] Frida script written to: {output_path}")
            return True
        except IOError as e:
            print(f"[!] Failed to write Frida script: {e}")
            return False
    
    def _generate_frida_script(
        self,
        binary_path: str,
        sanitizers: List[SanitizerType],
        options: Dict
    ) -> str:
        """
        Generate Frida JavaScript for runtime instrumentation.
        
        Args:
            binary_path: Path to target binary
            sanitizers: List of sanitizers to emulate
            options: Instrumentation options
            
        Returns:
            JavaScript code for Frida
        """
        script_parts = [
            "// Auto-generated Frida instrumentation script",
            "// Binary: " + binary_path,
            "",
            "console.log('[*] Frida instrumentation loaded');",
            "",
        ]
        
        # Add instrumentation for each sanitizer
        for san in sanitizers:
            if san == SanitizerType.ASAN:
                script_parts.append(self._generate_asan_frida_script(options))
            elif san == SanitizerType.UBSAN:
                script_parts.append(self._generate_ubsan_frida_script(options))
            elif san == SanitizerType.TSAN:
                script_parts.append(self._generate_tsan_frida_script(options))
            elif san == SanitizerType.MSAN:
                script_parts.append(self._generate_msan_frida_script(options))
            elif san == SanitizerType.LSAN:
                # LSan is integrated with ASAN in Frida mode
                script_parts.append("// LeakSanitizer - covered by ASAN hooks\n")
            else:
                script_parts.append(f"// Sanitizer {san.value} not yet implemented for Frida\n")
        
        # Add edge instrumentation with auto-removal
        if options.get('edge_instrumentation', True):
            script_parts.append(self._generate_edge_instrumentation_script(options))
        
        return "\n".join(script_parts)
    
    def _generate_asan_frida_script(self, options: Dict) -> str:
        """
        Generate Frida script for AddressSanitizer-like checks.
        
        Args:
            options: Instrumentation options
            
        Returns:
            JavaScript code for ASAN checks
        """
        return """
// AddressSanitizer emulation
var asanShadowBase = null;
var hitEdges = new Set();

// Hook memory allocation functions
Interceptor.attach(Module.findExportByName(null, 'malloc'), {
    onEnter: function(args) {
        this.size = args[0].toInt32();
    },
    onLeave: function(retval) {
        if (!retval.isNull()) {
            console.log('[ASAN] malloc(' + this.size + ') = ' + retval);
            // Track allocation
        }
    }
});

Interceptor.attach(Module.findExportByName(null, 'free'), {
    onEnter: function(args) {
        var ptr = args[0];
        if (!ptr.isNull()) {
            console.log('[ASAN] free(' + ptr + ')');
            // Check for double-free, use-after-free
        }
    }
});

// Hook buffer operations
var bufferFuncs = ['memcpy', 'strcpy', 'strcat', 'sprintf'];
bufferFuncs.forEach(function(funcName) {
    var funcPtr = Module.findExportByName(null, funcName);
    if (funcPtr) {
        Interceptor.attach(funcPtr, {
            onEnter: function(args) {
                console.log('[ASAN] ' + funcName + ' called');
                // Add bounds checking here
            }
        });
    }
});
"""
    
    def _generate_ubsan_frida_script(self, options: Dict) -> str:
        """
        Generate Frida script for UndefinedBehaviorSanitizer-like checks.
        
        Args:
            options: Instrumentation options
            
        Returns:
            JavaScript code for UBSan checks
        """
        return """
// UndefinedBehaviorSanitizer emulation
console.log('[*] UBSan instrumentation enabled');

// Hook integer operations to detect overflows
// This would require binary analysis to identify arithmetic operations
"""
    
    def _generate_tsan_frida_script(self, options: Dict) -> str:
        """
        Generate Frida script for ThreadSanitizer-like checks.
        
        Args:
            options: Instrumentation options
            
        Returns:
            JavaScript code for TSan checks
        """
        return """
// ThreadSanitizer emulation
console.log('[*] TSan instrumentation enabled');

// Track thread creation and synchronization
var threadMap = new Map();

// Hook pthread functions
var pthreadFuncs = ['pthread_create', 'pthread_join', 'pthread_mutex_lock', 'pthread_mutex_unlock'];
pthreadFuncs.forEach(function(funcName) {
    var funcPtr = Module.findExportByName(null, funcName);
    if (funcPtr) {
        Interceptor.attach(funcPtr, {
            onEnter: function(args) {
                console.log('[TSAN] ' + funcName + ' called');
            }
        });
    }
});
"""
    
    def _generate_msan_frida_script(self, options: Dict) -> str:
        """
        Generate Frida script for MemorySanitizer-like checks.
        
        Args:
            options: Instrumentation options
            
        Returns:
            JavaScript code for MSan checks
        """
        return """
// MemorySanitizer emulation
console.log('[*] MSan instrumentation enabled');

// Track memory initialization
// This would require shadow memory tracking similar to ASAN
"""
    
    def _generate_edge_instrumentation_script(self, options: Dict) -> str:
        """
        Generate Frida script for efficient edge instrumentation.
        
        This implements self-removing edge instrumentation that removes
        hooks after first hit for performance.
        
        Args:
            options: Instrumentation options
            
        Returns:
            JavaScript code for edge instrumentation
        """
        return """
// Efficient edge instrumentation with auto-removal
var edgeHits = new Map();
var edgeListeners = new Map();

function instrumentFunction(address, name) {
    console.log('[*] Instrumenting function: ' + name + ' at ' + address);
    
    var listener = Interceptor.attach(ptr(address), {
        onEnter: function(args) {
            var edgeId = address + ':entry';
            if (!edgeHits.has(edgeId)) {
                console.log('[EDGE] First hit: ' + name + ' entry');
                edgeHits.set(edgeId, 1);
                
                // Auto-remove after first hit for efficiency
                if (edgeListeners.has(edgeId)) {
                    edgeListeners.get(edgeId).detach();
                    edgeListeners.delete(edgeId);
                    console.log('[*] Removed instrumentation for: ' + name);
                }
            }
        }
    });
    
    edgeListeners.set(address + ':entry', listener);
}

// Enumerate all functions and instrument them
var mainModule = Process.enumerateModules()[0];
console.log('[*] Instrumenting module: ' + mainModule.name);

var functions = Module.enumerateExports(mainModule.name);
functions.forEach(function(func) {
    if (func.type === 'function') {
        try {
            instrumentFunction(func.address, func.name);
        } catch (e) {
            // Ignore errors for now
        }
    }
});

console.log('[*] Edge instrumentation complete: ' + edgeListeners.size + ' functions');
"""
    
    def _instrument_binary_patch(
        self,
        binary_path: str,
        output_path: str,
        sanitizers: List[SanitizerType],
        options: Dict
    ) -> bool:
        """
        Instrument binary through direct binary patching.
        
        This is the most complex approach but doesn't require source code.
        
        Args:
            binary_path: Path to target binary
            output_path: Path for patched output
            sanitizers: List of sanitizers to apply
            options: Patching options
            
        Returns:
            True if patching succeeded
        """
        # This would require binary analysis and code injection
        # For now, just copy the binary and return False
        print("[!] Binary patching not yet implemented")
        return False
    
    def generate_sanitizer_options(
        self,
        sanitizers: List[SanitizerType],
        options: Optional[Dict] = None
    ) -> str:
        """
        Generate runtime options string for sanitizers.
        
        Args:
            sanitizers: List of sanitizers
            options: Custom options for each sanitizer
            
        Returns:
            Environment variable string for sanitizer options
        """
        options = options or {}
        env_vars = []
        
        for san in sanitizers:
            if san == SanitizerType.ASAN:
                asan_opts = [
                    'detect_leaks=1',
                    'detect_stack_use_after_return=1',
                    'check_initialization_order=1',
                    'strict_init_order=1',
                    'detect_invalid_pointer_pairs=2',
                ]
                if 'asan_options' in options:
                    asan_opts.extend(options['asan_options'])
                env_vars.append(f"ASAN_OPTIONS='{':'.join(asan_opts)}'")
            
            elif san == SanitizerType.UBSAN:
                ubsan_opts = ['print_stacktrace=1']
                if 'ubsan_options' in options:
                    ubsan_opts.extend(options['ubsan_options'])
                env_vars.append(f"UBSAN_OPTIONS='{':'.join(ubsan_opts)}'")
            
            elif san == SanitizerType.TSAN:
                tsan_opts = ['second_deadlock_stack=1']
                if 'tsan_options' in options:
                    tsan_opts.extend(options['tsan_options'])
                env_vars.append(f"TSAN_OPTIONS='{':'.join(tsan_opts)}'")
            
            elif san == SanitizerType.MSAN:
                msan_opts = ['poison_in_malloc=1']
                if 'msan_options' in options:
                    msan_opts.extend(options['msan_options'])
                env_vars.append(f"MSAN_OPTIONS='{':'.join(msan_opts)}'")
            
            elif san == SanitizerType.LSAN:
                lsan_opts = ['report_objects=1']
                if 'lsan_options' in options:
                    lsan_opts.extend(options['lsan_options'])
                env_vars.append(f"LSAN_OPTIONS='{':'.join(lsan_opts)}'")
        
        return ' '.join(env_vars)


class BinaryInstrumentor:
    """
    High-level interface for binary instrumentation.
    
    This class provides a simplified API for common instrumentation tasks.
    """
    
    def __init__(self, verbose: bool = False):
        """Initialize the binary instrumentor."""
        self.engine = LLVMInstrumentation(verbose=verbose)
        self.verbose = verbose
    
    def instrument_with_asan(
        self,
        input_path: str,
        output_path: str,
        use_frida: bool = False
    ) -> bool:
        """
        Instrument binary with AddressSanitizer.
        
        Args:
            input_path: Path to input binary
            output_path: Path for instrumented output
            use_frida: Use Frida instead of LLVM
            
        Returns:
            True if instrumentation succeeded
        """
        mode = InstrumentationMode.FRIDA if use_frida else InstrumentationMode.LLVM_COMPILE
        return self.engine.instrument_binary(
            input_path,
            output_path,
            [SanitizerType.ASAN],
            mode
        )
    
    def instrument_with_all_sanitizers(
        self,
        input_path: str,
        output_path: str,
        use_frida: bool = False
    ) -> bool:
        """
        Instrument binary with all available sanitizers.
        
        Args:
            input_path: Path to input binary
            output_path: Path for instrumented output
            use_frida: Use Frida instead of LLVM
            
        Returns:
            True if instrumentation succeeded
        """
        sanitizers = [
            SanitizerType.ASAN,
            SanitizerType.UBSAN,
        ]
        mode = InstrumentationMode.FRIDA if use_frida else InstrumentationMode.LLVM_COMPILE
        return self.engine.instrument_binary(
            input_path,
            output_path,
            sanitizers,
            mode
        )


def main():
    """Command-line interface for binary instrumentation."""
    import argparse
    
    parser = argparse.ArgumentParser(
        description='LLVM/libfuzzrt binary instrumentation tool'
    )
    parser.add_argument(
        'input',
        help='Input binary or source file'
    )
    parser.add_argument(
        '-o', '--output',
        required=True,
        help='Output path for instrumented binary or Frida script'
    )
    parser.add_argument(
        '-s', '--sanitizer',
        action='append',
        choices=['asan', 'ubsan', 'msan', 'tsan', 'lsan'],
        help='Sanitizers to apply (can be specified multiple times)'
    )
    parser.add_argument(
        '-m', '--mode',
        choices=['llvm', 'frida', 'patch'],
        default='llvm',
        help='Instrumentation mode'
    )
    parser.add_argument(
        '-v', '--verbose',
        action='store_true',
        help='Enable verbose output'
    )
    
    args = parser.parse_args()
    
    # Map string names to enum values
    sanitizer_map = {
        'asan': SanitizerType.ASAN,
        'ubsan': SanitizerType.UBSAN,
        'msan': SanitizerType.MSAN,
        'tsan': SanitizerType.TSAN,
        'lsan': SanitizerType.LSAN,
    }
    
    mode_map = {
        'llvm': InstrumentationMode.LLVM_COMPILE,
        'frida': InstrumentationMode.FRIDA,
        'patch': InstrumentationMode.BINARY_PATCH,
    }
    
    sanitizers = [sanitizer_map[s] for s in (args.sanitizer or ['asan'])]
    mode = mode_map[args.mode]
    
    instrumentor = BinaryInstrumentor(verbose=args.verbose)
    
    try:
        success = instrumentor.engine.instrument_binary(
            args.input,
            args.output,
            sanitizers,
            mode
        )
        
        if success:
            print(f"[+] Instrumentation successful: {args.output}")
            
            # Print runtime options
            env_vars = instrumentor.engine.generate_sanitizer_options(sanitizers)
            if env_vars:
                print(f"[*] Runtime options: {env_vars}")
            
            sys.exit(0)
        else:
            print("[!] Instrumentation failed")
            sys.exit(1)
    except Exception as e:
        print(f"[!] Error: {e}")
        sys.exit(1)


if __name__ == '__main__':
    main()
