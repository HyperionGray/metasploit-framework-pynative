#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
Test suite for LLVM/libfuzzrt instrumentation module

This test validates the basic functionality of the LLVM instrumentation
utility without requiring LLVM or Frida to be installed.
"""

import unittest
import sys
import os
import tempfile

# Add lib directory to path
lib_path = os.path.abspath(os.path.join(os.path.dirname(__file__), '..', 'lib'))
sys.path.insert(0, lib_path)

# Import the module directly since it's a standalone Python file
import importlib.util
spec = importlib.util.spec_from_file_location(
    "llvm_instrumentation",
    os.path.join(lib_path, 'msf', 'util', 'llvm_instrumentation.py')
)
llvm_instrumentation = importlib.util.module_from_spec(spec)
spec.loader.exec_module(llvm_instrumentation)

# Import classes
LLVMInstrumentation = llvm_instrumentation.LLVMInstrumentation
BinaryInstrumentor = llvm_instrumentation.BinaryInstrumentor
SanitizerType = llvm_instrumentation.SanitizerType
InstrumentationMode = llvm_instrumentation.InstrumentationMode


class TestLLVMInstrumentation(unittest.TestCase):
    """Test cases for LLVM instrumentation core functionality"""
    
    def setUp(self):
        """Set up test fixtures"""
        self.engine = LLVMInstrumentation(verbose=False)
    
    def test_initialization(self):
        """Test that the engine initializes correctly"""
        self.assertIsNotNone(self.engine)
        self.assertIsInstance(self.engine.llvm_path, dict)
        self.assertIsInstance(self.engine.frida_available, bool)
    
    def test_which_utility(self):
        """Test the which utility for finding executables"""
        # Test with a command that should exist
        result = self.engine._which('python3')
        self.assertIsNotNone(result, "python3 should be found in PATH")
        
        # Test with a command that shouldn't exist
        result = self.engine._which('nonexistent_command_12345')
        self.assertIsNone(result)
    
    def test_llvm_tool_detection(self):
        """Test LLVM tool detection"""
        paths = self.engine.llvm_path
        self.assertIn('clang', paths)
        self.assertIn('clang++', paths)
        # Note: clang may or may not be installed, so we just check the keys exist
    
    def test_sanitizer_enum(self):
        """Test SanitizerType enum"""
        self.assertEqual(SanitizerType.ASAN.value, 'address')
        self.assertEqual(SanitizerType.UBSAN.value, 'undefined')
        self.assertEqual(SanitizerType.MSAN.value, 'memory')
        self.assertEqual(SanitizerType.TSAN.value, 'thread')
        self.assertEqual(SanitizerType.LSAN.value, 'leak')
    
    def test_instrumentation_mode_enum(self):
        """Test InstrumentationMode enum"""
        self.assertEqual(InstrumentationMode.LLVM_COMPILE.value, 'llvm_compile')
        self.assertEqual(InstrumentationMode.FRIDA.value, 'frida')
        self.assertEqual(InstrumentationMode.BINARY_PATCH.value, 'binary_patch')
    
    def test_generate_sanitizer_options(self):
        """Test sanitizer options generation"""
        options = self.engine.generate_sanitizer_options([SanitizerType.ASAN])
        self.assertIn('ASAN_OPTIONS', options)
        self.assertIn('detect_leaks=1', options)
        
        # Test multiple sanitizers
        options = self.engine.generate_sanitizer_options(
            [SanitizerType.ASAN, SanitizerType.UBSAN]
        )
        self.assertIn('ASAN_OPTIONS', options)
        self.assertIn('UBSAN_OPTIONS', options)
    
    def test_generate_frida_script(self):
        """Test Frida script generation"""
        script = self.engine._generate_frida_script(
            '/tmp/test_binary',
            [SanitizerType.ASAN],
            {'edge_instrumentation': True}
        )
        
        self.assertIsInstance(script, str)
        self.assertIn('Frida instrumentation', script)
        self.assertIn('AddressSanitizer', script)
        self.assertIn('Edge instrumentation', script)
        self.assertIn('malloc', script)
        self.assertIn('free', script)
    
    def test_generate_asan_frida_script(self):
        """Test ASAN Frida script generation"""
        script = self.engine._generate_asan_frida_script({})
        
        self.assertIn('malloc', script)
        self.assertIn('free', script)
        self.assertIn('memcpy', script)
        self.assertIn('ASAN', script)
    
    def test_generate_edge_instrumentation_script(self):
        """Test edge instrumentation script generation"""
        script = self.engine._generate_edge_instrumentation_script({})
        
        self.assertIn('edge', script.lower())
        self.assertIn('detach', script)
        self.assertIn('auto-removal', script.lower())
    
    def test_invalid_input_file(self):
        """Test handling of invalid input file"""
        with self.assertRaises(FileNotFoundError):
            self.engine.instrument_binary(
                '/nonexistent/file.c',
                '/tmp/output',
                [SanitizerType.ASAN],
                InstrumentationMode.LLVM_COMPILE
            )


class TestBinaryInstrumentor(unittest.TestCase):
    """Test cases for BinaryInstrumentor high-level API"""
    
    def setUp(self):
        """Set up test fixtures"""
        self.instrumentor = BinaryInstrumentor(verbose=False)
    
    def test_initialization(self):
        """Test instrumentor initialization"""
        self.assertIsNotNone(self.instrumentor)
        self.assertIsNotNone(self.instrumentor.engine)
    
    def test_engine_access(self):
        """Test that the underlying engine is accessible"""
        engine = self.instrumentor.engine
        self.assertIsInstance(engine, LLVMInstrumentation)


class TestFridaScriptGeneration(unittest.TestCase):
    """Test Frida script generation without requiring Frida"""
    
    def setUp(self):
        """Set up test fixtures"""
        self.engine = LLVMInstrumentation(verbose=False)
    
    def test_frida_script_file_creation(self):
        """Test creating a Frida script file"""
        with tempfile.NamedTemporaryFile(mode='w', suffix='.js', delete=False) as f:
            temp_path = f.name
        
        try:
            # Generate script content
            script = self.engine._generate_frida_script(
                '/tmp/test',
                [SanitizerType.ASAN, SanitizerType.UBSAN],
                {'edge_instrumentation': True}
            )
            
            # Write to file
            with open(temp_path, 'w') as f:
                f.write(script)
            
            # Verify file was created
            self.assertTrue(os.path.exists(temp_path))
            
            # Verify content
            with open(temp_path, 'r') as f:
                content = f.read()
            
            self.assertIn('Frida', content)
            self.assertIn('ASAN', content)
            self.assertIn('UBSan', content)
            
        finally:
            # Clean up
            if os.path.exists(temp_path):
                os.unlink(temp_path)


class TestSanitizerOptions(unittest.TestCase):
    """Test sanitizer option generation"""
    
    def setUp(self):
        """Set up test fixtures"""
        self.engine = LLVMInstrumentation(verbose=False)
    
    def test_asan_options(self):
        """Test ASAN options generation"""
        options = self.engine.generate_sanitizer_options([SanitizerType.ASAN])
        
        # Check all expected options are present
        self.assertIn('detect_leaks=1', options)
        self.assertIn('detect_stack_use_after_return=1', options)
        self.assertIn('check_initialization_order=1', options)
        self.assertIn('strict_init_order=1', options)
        self.assertIn('detect_invalid_pointer_pairs=2', options)
    
    def test_ubsan_options(self):
        """Test UBSan options generation"""
        options = self.engine.generate_sanitizer_options([SanitizerType.UBSAN])
        
        self.assertIn('UBSAN_OPTIONS', options)
        self.assertIn('print_stacktrace=1', options)
    
    def test_custom_options(self):
        """Test custom sanitizer options"""
        custom_opts = {
            'asan_options': ['custom_opt=1', 'another_opt=value']
        }
        
        options = self.engine.generate_sanitizer_options(
            [SanitizerType.ASAN],
            custom_opts
        )
        
        self.assertIn('custom_opt=1', options)
        self.assertIn('another_opt=value', options)


def run_tests():
    """Run all tests"""
    # Create test suite
    loader = unittest.TestLoader()
    suite = unittest.TestSuite()
    
    # Add all test classes
    suite.addTests(loader.loadTestsFromTestCase(TestLLVMInstrumentation))
    suite.addTests(loader.loadTestsFromTestCase(TestBinaryInstrumentor))
    suite.addTests(loader.loadTestsFromTestCase(TestFridaScriptGeneration))
    suite.addTests(loader.loadTestsFromTestCase(TestSanitizerOptions))
    
    # Run tests
    runner = unittest.TextTestRunner(verbosity=2)
    result = runner.run(suite)
    
    # Return exit code
    return 0 if result.wasSuccessful() else 1


if __name__ == '__main__':
    sys.exit(run_tests())
