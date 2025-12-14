"""
Radare2 Wrapper with GDB-like Commands

This module provides an intuitive interface to Radare2 with commands 
that mirror GDB syntax for easier adoption.
"""

import subprocess
import json
import re
from typing import Optional, List, Dict, Any


class Radare2Wrapper:
    """
    Wrapper around Radare2 (r2) providing GDB-like command interface.
    
    Command Mapping:
        GDB Command          -> Radare2 Command
        break <addr>         -> db <addr>
        run                  -> dc
        continue             -> dc
        step / si            -> ds
        stepi                -> ds
        next / ni            -> dso
        nexti                -> dso
        backtrace / bt       -> dbt
        info registers       -> dr
        print / x            -> px
        disassemble          -> pd
        list                 -> pdf
        info functions       -> afl
        info breakpoints     -> dbi
    """
    
    def __init__(self, binary_path: str, debug: bool = False):
        """
        Initialize Radare2 wrapper.
        
        Args:
            binary_path: Path to the binary to analyze
            debug: Enable debug mode for analysis
        """
        self.binary_path = binary_path
        self.debug_mode = debug
        self.r2_pipe = None
        self._init_r2pipe()
    
    def _init_r2pipe(self):
        """Initialize r2pipe connection"""
        try:
            import r2pipe
            flags = ['-2'] if self.debug_mode else []
            self.r2_pipe = r2pipe.open(self.binary_path, flags=flags)
            # Analyze the binary
            self.r2_pipe.cmd('aaa')  # Analyze all
        except ImportError:
            raise ImportError(
                "r2pipe not installed. Install with: pip install r2pipe"
            )
        except Exception as e:
            raise RuntimeError(f"Failed to initialize Radare2: {e}")
    
    def close(self):
        """Close r2pipe connection"""
        if self.r2_pipe:
            self.r2_pipe.quit()
            self.r2_pipe = None
    
    def __enter__(self):
        return self
    
    def __exit__(self, exc_type, exc_val, exc_tb):
        self.close()
    
    # GDB-like command interface
    
    def break_at(self, address: str) -> str:
        """
        Set breakpoint at address (GDB: break)
        
        Args:
            address: Address to set breakpoint (hex or symbol)
            
        Returns:
            Result message
        """
        return self.r2_pipe.cmd(f'db {address}')
    
    def run(self) -> str:
        """Start or continue program execution (GDB: run)"""
        return self.r2_pipe.cmd('dc')
    
    def continue_exec(self) -> str:
        """Continue execution (GDB: continue)"""
        return self.r2_pipe.cmd('dc')
    
    def step(self) -> str:
        """Step into (GDB: step/si)"""
        return self.r2_pipe.cmd('ds')
    
    def stepi(self) -> str:
        """Step one instruction (GDB: stepi)"""
        return self.r2_pipe.cmd('ds')
    
    def next(self) -> str:
        """Step over (GDB: next/ni)"""
        return self.r2_pipe.cmd('dso')
    
    def nexti(self) -> str:
        """Step over one instruction (GDB: nexti)"""
        return self.r2_pipe.cmd('dso')
    
    def backtrace(self) -> str:
        """Show backtrace (GDB: backtrace/bt)"""
        return self.r2_pipe.cmd('dbt')
    
    def info_registers(self) -> Dict[str, Any]:
        """
        Get register values (GDB: info registers)
        
        Returns:
            Dictionary of register names to values
        """
        result = self.r2_pipe.cmdj('drj')
        return result if result else {}
    
    def print_memory(self, address: str, size: int = 64, format: str = 'hex') -> str:
        """
        Print memory contents (GDB: x)
        
        Args:
            address: Memory address to examine
            size: Number of bytes to display
            format: Display format ('hex', 'str', 'disasm')
            
        Returns:
            Formatted memory contents
        """
        if format == 'hex':
            return self.r2_pipe.cmd(f'px {size} @ {address}')
        elif format == 'str':
            return self.r2_pipe.cmd(f'ps @ {address}')
        elif format == 'disasm':
            return self.r2_pipe.cmd(f'pd {size} @ {address}')
        else:
            return self.r2_pipe.cmd(f'px {size} @ {address}')
    
    def disassemble(self, address: Optional[str] = None, lines: int = 10) -> str:
        """
        Disassemble code (GDB: disassemble)
        
        Args:
            address: Address to disassemble (None for current)
            lines: Number of instructions to disassemble
            
        Returns:
            Disassembled code
        """
        if address:
            return self.r2_pipe.cmd(f'pd {lines} @ {address}')
        else:
            return self.r2_pipe.cmd(f'pd {lines}')
    
    def list_functions(self) -> List[Dict[str, Any]]:
        """
        List all functions (GDB: info functions)
        
        Returns:
            List of function dictionaries
        """
        result = self.r2_pipe.cmdj('aflj')
        return result if result else []
    
    def info_breakpoints(self) -> str:
        """Show breakpoints (GDB: info breakpoints)"""
        return self.r2_pipe.cmd('dbi')
    
    def delete_breakpoint(self, address: str) -> str:
        """Delete breakpoint (GDB: delete)"""
        return self.r2_pipe.cmd(f'db- {address}')
    
    def set_register(self, register: str, value: str) -> str:
        """
        Set register value (GDB: set $reg = value)
        
        Args:
            register: Register name
            value: Value to set
            
        Returns:
            Result message
        """
        return self.r2_pipe.cmd(f'dr {register}={value}')
    
    def get_register(self, register: str) -> str:
        """
        Get register value (GDB: print $reg)
        
        Args:
            register: Register name
            
        Returns:
            Register value as string
        """
        return self.r2_pipe.cmd(f'dr {register}').strip()
    
    # Additional Radare2-specific features
    
    def analyze_function(self, address: str) -> str:
        """Analyze function at address"""
        return self.r2_pipe.cmd(f'af @ {address}')
    
    def find_strings(self, min_length: int = 4) -> List[Dict[str, Any]]:
        """
        Find strings in binary
        
        Args:
            min_length: Minimum string length
            
        Returns:
            List of string dictionaries
        """
        result = self.r2_pipe.cmdj('izj')
        if result:
            return [s for s in result if len(s.get('string', '')) >= min_length]
        return []
    
    def find_xrefs_to(self, address: str) -> List[Dict[str, Any]]:
        """
        Find cross-references to address
        
        Args:
            address: Target address
            
        Returns:
            List of xref dictionaries
        """
        result = self.r2_pipe.cmdj(f'axtj @ {address}')
        return result if result else []
    
    def find_xrefs_from(self, address: str) -> List[Dict[str, Any]]:
        """
        Find cross-references from address
        
        Args:
            address: Source address
            
        Returns:
            List of xref dictionaries
        """
        result = self.r2_pipe.cmdj(f'axfj @ {address}')
        return result if result else []
    
    def seek(self, address: str) -> str:
        """Seek to address"""
        return self.r2_pipe.cmd(f's {address}')
    
    def get_current_address(self) -> str:
        """Get current seek address"""
        return self.r2_pipe.cmd('s').strip()
    
    def execute_command(self, cmd: str) -> str:
        """
        Execute raw Radare2 command
        
        Args:
            cmd: Radare2 command to execute
            
        Returns:
            Command output
        """
        return self.r2_pipe.cmd(cmd)
    
    def execute_command_json(self, cmd: str) -> Any:
        """
        Execute Radare2 command with JSON output
        
        Args:
            cmd: Radare2 command to execute (should end with 'j')
            
        Returns:
            Parsed JSON result
        """
        return self.r2_pipe.cmdj(cmd)
    
    # Binary information
    
    def get_binary_info(self) -> Dict[str, Any]:
        """Get binary information"""
        return self.r2_pipe.cmdj('ij') or {}
    
    def get_entry_point(self) -> str:
        """Get entry point address"""
        info = self.get_binary_info()
        bin_info = info.get('bin', {})
        return hex(bin_info.get('baddr', 0))
    
    def get_sections(self) -> List[Dict[str, Any]]:
        """Get binary sections"""
        return self.r2_pipe.cmdj('iSj') or []
    
    def get_imports(self) -> List[Dict[str, Any]]:
        """Get imported functions"""
        return self.r2_pipe.cmdj('iij') or []
    
    def get_exports(self) -> List[Dict[str, Any]]:
        """Get exported functions"""
        return self.r2_pipe.cmdj('iEj') or []
    
    def get_symbols(self) -> List[Dict[str, Any]]:
        """Get symbols"""
        return self.r2_pipe.cmdj('isj') or []


def main():
    """Example usage"""
    import sys
    
    if len(sys.argv) < 2:
        print("Usage: python radare2_wrapper.py <binary_path>")
        sys.exit(1)
    
    binary = sys.argv[1]
    
    print(f"Analyzing {binary}...")
    
    with Radare2Wrapper(binary) as r2:
        # Get binary info
        info = r2.get_binary_info()
        print(f"\nBinary: {info.get('core', {}).get('file', 'Unknown')}")
        print(f"Arch: {info.get('bin', {}).get('arch', 'Unknown')}")
        print(f"Bits: {info.get('bin', {}).get('bits', 'Unknown')}")
        
        # List functions
        functions = r2.list_functions()
        print(f"\nFound {len(functions)} functions")
        if functions:
            print("\nFirst 5 functions:")
            for func in functions[:5]:
                print(f"  {func.get('name', 'Unknown')} @ {hex(func.get('offset', 0))}")
        
        # Find strings
        strings = r2.find_strings(min_length=8)
        print(f"\nFound {len(strings)} strings (min length 8)")
        if strings:
            print("\nFirst 5 strings:")
            for s in strings[:5]:
                print(f"  {s.get('string', '')[:60]}")


if __name__ == '__main__':
    main()
