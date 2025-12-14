"""
LLDB Debugger Integration

Provides LLDB debugging capabilities with a clean Python interface.
"""

import subprocess
import re
from typing import Optional, List, Dict, Any, Tuple


class LLDBDebugger:
    """
    LLDB debugger wrapper for dynamic binary analysis and debugging.
    
    Features:
    - Set breakpoints and watchpoints
    - Step through execution
    - Examine memory and registers
    - Evaluate expressions
    - Script debugging workflows
    """
    
    def __init__(self, binary_path: str, args: Optional[List[str]] = None):
        """
        Initialize LLDB debugger.
        
        Args:
            binary_path: Path to the binary to debug
            args: Optional command-line arguments for the binary
        """
        self.binary_path = binary_path
        self.args = args or []
        self.lldb_process = None
        self.breakpoints = {}
        self.watchpoints = {}
        self._check_lldb()
    
    def _check_lldb(self):
        """Check if LLDB is available"""
        try:
            result = subprocess.run(
                ['lldb', '--version'],
                capture_output=True,
                text=True,
                timeout=5
            )
            if result.returncode != 0:
                raise RuntimeError("LLDB not available")
        except (subprocess.TimeoutExpired, FileNotFoundError):
            raise RuntimeError(
                "LLDB not found. Please install LLDB:\n"
                "  Ubuntu/Debian: apt-get install lldb\n"
                "  macOS: xcode-select --install\n"
                "  Homebrew: brew install llvm"
            )
    
    def start(self) -> bool:
        """
        Start LLDB debugging session.
        
        Returns:
            True if successfully started
        """
        try:
            import lldb
            self.debugger = lldb.SBDebugger.Create()
            self.debugger.SetAsync(False)
            
            # Create target
            self.target = self.debugger.CreateTarget(self.binary_path)
            if not self.target:
                raise RuntimeError(f"Failed to create target for {self.binary_path}")
            
            # Launch process
            launch_info = lldb.SBLaunchInfo(self.args)
            launch_info.SetWorkingDirectory(None)
            
            error = lldb.SBError()
            self.process = self.target.Launch(launch_info, error)
            
            if error.Fail():
                raise RuntimeError(f"Failed to launch: {error.GetCString()}")
            
            return True
            
        except ImportError:
            raise ImportError(
                "lldb Python module not found. Install with:\n"
                "  pip install lldb-python\n"
                "Or use system LLDB Python bindings"
            )
    
    def stop(self):
        """Stop debugging session"""
        if hasattr(self, 'process') and self.process:
            self.process.Kill()
        if hasattr(self, 'debugger') and self.debugger:
            lldb.SBDebugger.Destroy(self.debugger)
    
    def __enter__(self):
        self.start()
        return self
    
    def __exit__(self, exc_type, exc_val, exc_tb):
        self.stop()
    
    # Breakpoint management
    
    def set_breakpoint(self, location: str, condition: Optional[str] = None) -> int:
        """
        Set breakpoint at location.
        
        Args:
            location: Function name, file:line, or address
            condition: Optional condition expression
            
        Returns:
            Breakpoint ID
        """
        if location.startswith('0x'):
            # Address breakpoint
            addr = int(location, 16)
            bp = self.target.BreakpointCreateByAddress(addr)
        elif ':' in location:
            # File:line breakpoint
            file, line = location.split(':', 1)
            bp = self.target.BreakpointCreateByLocation(file, int(line))
        else:
            # Function name breakpoint
            bp = self.target.BreakpointCreateByName(location)
        
        if condition:
            bp.SetCondition(condition)
        
        bp_id = bp.GetID()
        self.breakpoints[bp_id] = bp
        return bp_id
    
    def delete_breakpoint(self, bp_id: int) -> bool:
        """Delete breakpoint by ID"""
        if bp_id in self.breakpoints:
            self.target.BreakpointDelete(bp_id)
            del self.breakpoints[bp_id]
            return True
        return False
    
    def list_breakpoints(self) -> List[Dict[str, Any]]:
        """List all breakpoints"""
        breakpoints = []
        for bp_id, bp in self.breakpoints.items():
            breakpoints.append({
                'id': bp_id,
                'enabled': bp.IsEnabled(),
                'hit_count': bp.GetHitCount(),
                'locations': bp.GetNumLocations()
            })
        return breakpoints
    
    def set_watchpoint(self, address: int, size: int, read: bool = True, 
                      write: bool = True) -> int:
        """
        Set watchpoint on memory.
        
        Args:
            address: Memory address to watch
            size: Size in bytes to watch
            read: Trigger on read access
            write: Trigger on write access
            
        Returns:
            Watchpoint ID
        """
        import lldb
        watch_type = 0
        if read:
            watch_type |= lldb.eWatchpointReadTypeRead
        if write:
            watch_type |= lldb.eWatchpointWriteTypeWrite
        
        error = lldb.SBError()
        wp = self.target.WatchAddress(address, size, watch_type, error)
        
        if error.Fail():
            raise RuntimeError(f"Failed to set watchpoint: {error.GetCString()}")
        
        wp_id = wp.GetID()
        self.watchpoints[wp_id] = wp
        return wp_id
    
    # Execution control
    
    def continue_exec(self) -> str:
        """Continue execution"""
        if self.process:
            self.process.Continue()
            return self._get_stop_reason()
        return "No active process"
    
    def step_over(self) -> str:
        """Step over (next line)"""
        thread = self.process.GetSelectedThread()
        if thread:
            thread.StepOver()
            return self._get_stop_reason()
        return "No active thread"
    
    def step_into(self) -> str:
        """Step into (step)"""
        thread = self.process.GetSelectedThread()
        if thread:
            thread.StepInto()
            return self._get_stop_reason()
        return "No active thread"
    
    def step_out(self) -> str:
        """Step out (finish)"""
        thread = self.process.GetSelectedThread()
        if thread:
            thread.StepOut()
            return self._get_stop_reason()
        return "No active thread"
    
    def step_instruction(self) -> str:
        """Step single instruction"""
        thread = self.process.GetSelectedThread()
        if thread:
            thread.StepInstruction(False)
            return self._get_stop_reason()
        return "No active thread"
    
    def _get_stop_reason(self) -> str:
        """Get reason for process stop"""
        import lldb
        thread = self.process.GetSelectedThread()
        if not thread:
            return "Unknown"
        
        stop_reason = thread.GetStopReason()
        reasons = {
            lldb.eStopReasonNone: "None",
            lldb.eStopReasonTrace: "Trace",
            lldb.eStopReasonBreakpoint: "Breakpoint",
            lldb.eStopReasonWatchpoint: "Watchpoint",
            lldb.eStopReasonSignal: "Signal",
            lldb.eStopReasonException: "Exception",
            lldb.eStopReasonExec: "Exec",
            lldb.eStopReasonPlanComplete: "Plan Complete",
        }
        return reasons.get(stop_reason, f"Unknown ({stop_reason})")
    
    # Memory and register access
    
    def read_memory(self, address: int, size: int) -> bytes:
        """
        Read memory from target.
        
        Args:
            address: Memory address
            size: Number of bytes to read
            
        Returns:
            Bytes read
        """
        import lldb
        error = lldb.SBError()
        data = self.process.ReadMemory(address, size, error)
        
        if error.Fail():
            raise RuntimeError(f"Failed to read memory: {error.GetCString()}")
        
        return data
    
    def write_memory(self, address: int, data: bytes) -> bool:
        """
        Write memory to target.
        
        Args:
            address: Memory address
            data: Bytes to write
            
        Returns:
            True if successful
        """
        import lldb
        error = lldb.SBError()
        self.process.WriteMemory(address, data, error)
        
        if error.Fail():
            raise RuntimeError(f"Failed to write memory: {error.GetCString()}")
        
        return True
    
    def get_registers(self) -> Dict[str, int]:
        """
        Get all register values.
        
        Returns:
            Dictionary of register names to values
        """
        registers = {}
        thread = self.process.GetSelectedThread()
        if not thread:
            return registers
        
        frame = thread.GetSelectedFrame()
        if not frame:
            return registers
        
        for reg_set in frame.GetRegisters():
            for reg in reg_set:
                registers[reg.GetName()] = int(reg.GetValue(), 0)
        
        return registers
    
    def get_register(self, name: str) -> Optional[int]:
        """
        Get specific register value.
        
        Args:
            name: Register name
            
        Returns:
            Register value or None
        """
        registers = self.get_registers()
        return registers.get(name)
    
    def set_register(self, name: str, value: int) -> bool:
        """
        Set register value.
        
        Args:
            name: Register name
            value: New value
            
        Returns:
            True if successful
        """
        thread = self.process.GetSelectedThread()
        if not thread:
            return False
        
        frame = thread.GetSelectedFrame()
        if not frame:
            return False
        
        for reg_set in frame.GetRegisters():
            for reg in reg_set:
                if reg.GetName() == name:
                    return reg.SetValueFromCString(hex(value))
        
        return False
    
    # Stack and backtrace
    
    def get_backtrace(self) -> List[Dict[str, Any]]:
        """
        Get call stack backtrace.
        
        Returns:
            List of stack frames
        """
        backtrace = []
        thread = self.process.GetSelectedThread()
        if not thread:
            return backtrace
        
        for frame in thread:
            frame_info = {
                'index': frame.GetFrameID(),
                'pc': frame.GetPC(),
                'function': frame.GetFunctionName() or 'Unknown',
                'module': frame.GetModule().GetFileSpec().GetFilename() if frame.GetModule() else None,
            }
            
            line_entry = frame.GetLineEntry()
            if line_entry:
                frame_info['file'] = line_entry.GetFileSpec().GetFilename()
                frame_info['line'] = line_entry.GetLine()
            
            backtrace.append(frame_info)
        
        return backtrace
    
    def get_frame_variables(self, frame_index: int = 0) -> Dict[str, Any]:
        """
        Get local variables for a stack frame.
        
        Args:
            frame_index: Frame index (0 = current)
            
        Returns:
            Dictionary of variable names to values
        """
        variables = {}
        thread = self.process.GetSelectedThread()
        if not thread:
            return variables
        
        frame = thread.GetFrameAtIndex(frame_index)
        if not frame:
            return variables
        
        for var in frame.GetVariables(True, True, True, True):
            variables[var.GetName()] = var.GetValue()
        
        return variables
    
    # Expression evaluation
    
    def evaluate(self, expression: str) -> Optional[Any]:
        """
        Evaluate expression in current context.
        
        Args:
            expression: Expression to evaluate
            
        Returns:
            Result value or None
        """
        thread = self.process.GetSelectedThread()
        if not thread:
            return None
        
        frame = thread.GetSelectedFrame()
        if not frame:
            return None
        
        result = frame.EvaluateExpression(expression)
        if result.IsValid():
            return result.GetValue()
        
        return None
    
    # Utility methods
    
    def get_process_info(self) -> Dict[str, Any]:
        """Get process information"""
        if not self.process:
            return {}
        
        import lldb
        return {
            'pid': self.process.GetProcessID(),
            'state': self.process.GetState(),
            'state_name': lldb.SBDebugger.StateAsCString(self.process.GetState()),
            'exit_status': self.process.GetExitStatus() if self.process.GetState() == lldb.eStateExited else None,
        }
    
    def get_loaded_modules(self) -> List[Dict[str, Any]]:
        """Get list of loaded modules"""
        modules = []
        if not self.target:
            return modules
        
        for module in self.target.module_iter():
            file_spec = module.GetFileSpec()
            modules.append({
                'name': file_spec.GetFilename(),
                'path': file_spec.GetDirectory() + '/' + file_spec.GetFilename(),
                'uuid': str(module.GetUUIDString()),
            })
        
        return modules


def main():
    """Example usage"""
    import sys
    
    if len(sys.argv) < 2:
        print("Usage: python lldb_debugger.py <binary_path> [args...]")
        sys.exit(1)
    
    binary = sys.argv[1]
    args = sys.argv[2:] if len(sys.argv) > 2 else []
    
    print(f"Starting LLDB debugger for {binary}...")
    
    try:
        with LLDBDebugger(binary, args) as debugger:
            print("Debugger started successfully")
            print(f"Process info: {debugger.get_process_info()}")
            
            # Set breakpoint at main
            bp_id = debugger.set_breakpoint('main')
            print(f"Breakpoint set at main (ID: {bp_id})")
            
            # Continue to breakpoint
            print(f"Continuing... {debugger.continue_exec()}")
            
            # Show registers
            registers = debugger.get_registers()
            print(f"\nRegister dump ({len(registers)} registers):")
            for name, value in list(registers.items())[:10]:
                print(f"  {name}: 0x{value:x}")
            
            # Show backtrace
            backtrace = debugger.get_backtrace()
            print(f"\nBacktrace ({len(backtrace)} frames):")
            for frame in backtrace[:5]:
                print(f"  #{frame['index']}: {frame['function']} @ 0x{frame['pc']:x}")
    
    except Exception as e:
        print(f"Error: {e}")
        sys.exit(1)


if __name__ == '__main__':
    main()
