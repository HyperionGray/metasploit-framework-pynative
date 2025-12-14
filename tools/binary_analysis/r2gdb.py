#!/usr/bin/env python3
"""
R2GDB - Radare2 with GDB-like Commands

Interactive debugger combining Radare2's power with GDB's familiar interface.
"""

import sys
import os
import cmd
import shlex

# Add lib to path
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', '..', 'lib'))

from rex.binary_analysis import Radare2Wrapper


class R2GDB(cmd.Cmd):
    """
    Interactive GDB-like interface for Radare2.
    """
    
    intro = """
╔══════════════════════════════════════════════════════════════╗
║              R2GDB - Radare2 with GDB Commands              ║
║                                                              ║
║  A friendly interface to Radare2 using GDB-like commands    ║
╚══════════════════════════════════════════════════════════════╝

Type 'help' or '?' for a list of commands.
Type 'help <command>' for detailed help on a command.
    """
    
    prompt = '(r2gdb) '
    
    def __init__(self, binary_path: str):
        """Initialize R2GDB"""
        super().__init__()
        self.binary_path = binary_path
        self.r2 = None
        
        try:
            print(f"Loading binary: {binary_path}")
            self.r2 = Radare2Wrapper(binary_path)
            print("✓ Binary loaded successfully")
            
            # Show basic info
            info = self.r2.get_binary_info()
            if info:
                print(f"\nArchitecture: {info.get('bin', {}).get('arch', 'Unknown')}")
                print(f"Bits: {info.get('bin', {}).get('bits', 'Unknown')}")
                print(f"Entry point: {self.r2.get_entry_point()}")
        except Exception as e:
            print(f"Error loading binary: {e}")
            sys.exit(1)
    
    def do_break(self, arg):
        """Set breakpoint: break <address|function>"""
        if not arg:
            print("Usage: break <address|function>")
            return
        
        result = self.r2.break_at(arg)
        print(f"Breakpoint set at {arg}")
        if result:
            print(result)
    
    def do_b(self, arg):
        """Alias for break"""
        self.do_break(arg)
    
    def do_run(self, arg):
        """Start program execution: run"""
        result = self.r2.run()
        print(result)
    
    def do_r(self, arg):
        """Alias for run"""
        self.do_run(arg)
    
    def do_continue(self, arg):
        """Continue execution: continue"""
        result = self.r2.continue_exec()
        print(result)
    
    def do_c(self, arg):
        """Alias for continue"""
        self.do_continue(arg)
    
    def do_step(self, arg):
        """Step into: step"""
        result = self.r2.step()
        print(result)
    
    def do_s(self, arg):
        """Alias for step"""
        self.do_step(arg)
    
    def do_stepi(self, arg):
        """Step one instruction: stepi"""
        result = self.r2.stepi()
        print(result)
    
    def do_si(self, arg):
        """Alias for stepi"""
        self.do_stepi(arg)
    
    def do_next(self, arg):
        """Step over: next"""
        result = self.r2.next()
        print(result)
    
    def do_n(self, arg):
        """Alias for next"""
        self.do_next(arg)
    
    def do_nexti(self, arg):
        """Step over one instruction: nexti"""
        result = self.r2.nexti()
        print(result)
    
    def do_ni(self, arg):
        """Alias for nexti"""
        self.do_nexti(arg)
    
    def do_backtrace(self, arg):
        """Show backtrace: backtrace"""
        result = self.r2.backtrace()
        print(result)
    
    def do_bt(self, arg):
        """Alias for backtrace"""
        self.do_backtrace(arg)
    
    def do_info(self, arg):
        """Get information: info <registers|functions|breakpoints>"""
        if arg == 'registers' or arg == 'reg':
            regs = self.r2.info_registers()
            for name, value in regs.items():
                print(f"{name:10s} = {value}")
        elif arg == 'functions' or arg == 'func':
            functions = self.r2.list_functions()
            print(f"\nFound {len(functions)} functions:\n")
            for func in functions[:50]:  # Limit display
                print(f"{hex(func.get('offset', 0)):20s} {func.get('name', 'Unknown')}")
            if len(functions) > 50:
                print(f"\n... and {len(functions) - 50} more")
        elif arg == 'breakpoints' or arg == 'break':
            result = self.r2.info_breakpoints()
            print(result)
        else:
            print("Usage: info <registers|functions|breakpoints>")
    
    def do_i(self, arg):
        """Alias for info"""
        self.do_info(arg)
    
    def do_print(self, arg):
        """Print memory: print <address> [size] [format]
        Formats: hex, str, disasm"""
        parts = shlex.split(arg) if arg else []
        if not parts:
            print("Usage: print <address> [size] [format]")
            return
        
        address = parts[0]
        size = int(parts[1]) if len(parts) > 1 else 64
        fmt = parts[2] if len(parts) > 2 else 'hex'
        
        result = self.r2.print_memory(address, size, fmt)
        print(result)
    
    def do_x(self, arg):
        """Examine memory (alias for print): x <address> [size]"""
        self.do_print(arg)
    
    def do_disassemble(self, arg):
        """Disassemble code: disassemble [address] [lines]"""
        parts = shlex.split(arg) if arg else []
        
        address = parts[0] if parts else None
        lines = int(parts[1]) if len(parts) > 1 else 10
        
        result = self.r2.disassemble(address, lines)
        print(result)
    
    def do_disas(self, arg):
        """Alias for disassemble"""
        self.do_disassemble(arg)
    
    def do_list(self, arg):
        """List current function: list"""
        result = self.r2.disassemble(lines=20)
        print(result)
    
    def do_l(self, arg):
        """Alias for list"""
        self.do_list(arg)
    
    def do_delete(self, arg):
        """Delete breakpoint: delete <address>"""
        if not arg:
            print("Usage: delete <address>")
            return
        
        result = self.r2.delete_breakpoint(arg)
        print(f"Breakpoint deleted at {arg}")
    
    def do_set(self, arg):
        """Set register: set <register> <value>"""
        parts = shlex.split(arg) if arg else []
        if len(parts) < 2:
            print("Usage: set <register> <value>")
            return
        
        register = parts[0].replace('$', '')  # Remove $ if present
        value = parts[1]
        
        result = self.r2.set_register(register, value)
        print(f"Set {register} = {value}")
    
    def do_get(self, arg):
        """Get register: get <register>"""
        if not arg:
            print("Usage: get <register>")
            return
        
        register = arg.replace('$', '')
        value = self.r2.get_register(register)
        print(f"{register} = {value}")
    
    def do_strings(self, arg):
        """Find strings in binary: strings [min_length]"""
        min_len = int(arg) if arg else 8
        strings = self.r2.find_strings(min_len)
        
        print(f"\nFound {len(strings)} strings (min length {min_len}):\n")
        for s in strings[:100]:  # Limit display
            print(f"{hex(s.get('vaddr', 0)):20s} {s.get('string', '')[:60]}")
        
        if len(strings) > 100:
            print(f"\n... and {len(strings) - 100} more")
    
    def do_xrefs(self, arg):
        """Find cross-references: xrefs <to|from> <address>"""
        parts = shlex.split(arg) if arg else []
        if len(parts) < 2:
            print("Usage: xrefs <to|from> <address>")
            return
        
        direction = parts[0].lower()
        address = parts[1]
        
        if direction == 'to':
            xrefs = self.r2.find_xrefs_to(address)
            print(f"\nCross-references TO {address}:\n")
        elif direction == 'from':
            xrefs = self.r2.find_xrefs_from(address)
            print(f"\nCross-references FROM {address}:\n")
        else:
            print("Direction must be 'to' or 'from'")
            return
        
        for xref in xrefs:
            print(f"{hex(xref.get('from', 0)):20s} -> {hex(xref.get('to', 0))}")
    
    def do_seek(self, arg):
        """Seek to address: seek <address>"""
        if not arg:
            # Show current address
            addr = self.r2.get_current_address()
            print(f"Current address: {addr}")
        else:
            result = self.r2.seek(arg)
            print(f"Seeked to {arg}")
    
    def do_sections(self, arg):
        """Show binary sections: sections"""
        sections = self.r2.get_sections()
        
        print("\nBinary sections:\n")
        print(f"{'Name':<20} {'Address':<20} {'Size':<12} {'Perms':<8}")
        print("-" * 60)
        
        for section in sections:
            name = section.get('name', 'Unknown')
            addr = hex(section.get('vaddr', 0))
            size = section.get('size', 0)
            perm = section.get('perm', '')
            print(f"{name:<20} {addr:<20} {size:<12} {perm:<8}")
    
    def do_symbols(self, arg):
        """Show symbols: symbols"""
        symbols = self.r2.get_symbols()
        
        print(f"\nFound {len(symbols)} symbols:\n")
        print(f"{'Address':<20} {'Type':<10} {'Name'}")
        print("-" * 60)
        
        for sym in symbols[:100]:  # Limit display
            addr = hex(sym.get('vaddr', 0))
            sym_type = sym.get('type', 'Unknown')
            name = sym.get('name', 'Unknown')
            print(f"{addr:<20} {sym_type:<10} {name}")
        
        if len(symbols) > 100:
            print(f"\n... and {len(symbols) - 100} more")
    
    def do_imports(self, arg):
        """Show imported functions: imports"""
        imports = self.r2.get_imports()
        
        print(f"\nImported functions ({len(imports)}):\n")
        for imp in imports:
            print(f"{imp.get('name', 'Unknown')}")
    
    def do_exports(self, arg):
        """Show exported functions: exports"""
        exports = self.r2.get_exports()
        
        print(f"\nExported functions ({len(exports)}):\n")
        for exp in exports:
            print(f"{hex(exp.get('vaddr', 0)):<20} {exp.get('name', 'Unknown')}")
    
    def do_analyze(self, arg):
        """Analyze function: analyze <address>"""
        if not arg:
            print("Usage: analyze <address>")
            return
        
        result = self.r2.analyze_function(arg)
        print(f"Function analyzed at {arg}")
        print(result)
    
    def do_r2(self, arg):
        """Execute raw Radare2 command: r2 <command>"""
        if not arg:
            print("Usage: r2 <command>")
            return
        
        result = self.r2.execute_command(arg)
        print(result)
    
    def do_quit(self, arg):
        """Exit r2gdb: quit"""
        print("Goodbye!")
        return True
    
    def do_q(self, arg):
        """Alias for quit"""
        return self.do_quit(arg)
    
    def do_exit(self, arg):
        """Alias for quit"""
        return self.do_quit(arg)
    
    def do_EOF(self, arg):
        """Handle Ctrl-D"""
        print()
        return True
    
    def emptyline(self):
        """Do nothing on empty line"""
        pass
    
    def default(self, line):
        """Handle unknown commands"""
        print(f"Unknown command: {line}")
        print("Type 'help' for a list of commands")
    
    def __del__(self):
        """Cleanup"""
        if self.r2:
            self.r2.close()


def main():
    """Main entry point"""
    if len(sys.argv) < 2:
        print("R2GDB - Radare2 with GDB-like Commands")
        print("\nUsage: r2gdb.py <binary_path>")
        print("\nExample:")
        print("  r2gdb.py /bin/ls")
        sys.exit(1)
    
    binary = sys.argv[1]
    
    if not os.path.exists(binary):
        print(f"Error: Binary not found: {binary}")
        sys.exit(1)
    
    try:
        debugger = R2GDB(binary)
        debugger.cmdloop()
    except KeyboardInterrupt:
        print("\n\nInterrupted by user")
    except Exception as e:
        print(f"Error: {e}")
        sys.exit(1)


if __name__ == '__main__':
    main()
