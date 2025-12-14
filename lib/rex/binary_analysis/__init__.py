"""
Rex Binary Analysis Module

Provides advanced binary analysis capabilities including:
- Radare2 integration with GDB-like commands
- LLDB debugging support
- Binary instrumentation for coverage tracking
- In-memory fuzzing
"""

from .radare2_wrapper import Radare2Wrapper
from .lldb_debugger import LLDBDebugger
from .instrumentor import BinaryInstrumentor
from .fuzzer import InMemoryFuzzer

__all__ = ['Radare2Wrapper', 'LLDBDebugger', 'BinaryInstrumentor', 'InMemoryFuzzer']
