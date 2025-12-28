#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
Metasploit Framework Console - PyNative Version

This user interface provides users with a command console interface to the
framework. This is the Python-native implementation.
"""

import sys
import os
import argparse
import cmd
from pathlib import Path


class MsfConsole(cmd.Cmd):
    """Interactive Metasploit Framework Console"""
    
    # Version can be configured via environment variable or defaults to this
    VERSION = os.environ.get('MSF_VERSION', '6.4.0-pynative')
    
    intro = f'''
    =[ metasploit v{VERSION}                           ]
+ -- --=[ 2300+ exploits - 1300+ auxiliary - 400+ post       ]
+ -- --=[ 600+ payloads - 46 encoders - 11 nops             ]
+ -- --=[ 9 evasion                                          ]

🐍 Welcome to the PyNative Metasploit Framework Console!
'''
    prompt = 'msf6 > '
    
    def __init__(self):
        super().__init__()
        self.framework_root = Path(__file__).parent
        self.modules_dir = self.framework_root / 'modules'
        self.current_module = None
        self.module_options = {}
        self.search_limit = int(os.environ.get('MSF_SEARCH_LIMIT', '20'))
        
    def do_help(self, arg):
        """List available commands or show help for specific command"""
        if arg:
            try:
                func = getattr(self, f'do_{arg}')
                print(func.__doc__ or f"No help available for {arg}")
            except AttributeError:
                print(f"Unknown command: {arg}")
        else:
            print("\nCore Commands")
            print("=============")
            print("    ?            Help menu")
            print("    search       Search for modules")
            print("    use          Select a module by name")
            print("    show         Display modules of a given type, or all modules")
            print("    info         Display information about a module")
            print("    options      Display options for current module")
            print("    set          Set a context-specific variable to a value")
            print("    run          Run the current module")
            print("    back         Move back from current context")
            print("    exit         Exit the console")
            print()
            
    def do_search(self, arg):
        """Search for modules matching the query"""
        if not arg:
            print("Usage: search <query>")
            return
            
        print(f"\nSearching for: {arg}")
        print("="*70)
        
        # Search for Python modules
        found = []
        for pattern in ['exploits', 'auxiliary', 'post']:
            module_path = self.modules_dir / pattern
            if module_path.exists():
                for py_file in module_path.rglob('*.py'):
                    if '__init__' in py_file.name:
                        continue
                    rel_path = py_file.relative_to(self.modules_dir)
                    if arg.lower() in str(rel_path).lower():
                        found.append(str(rel_path))
        
        if found:
            for i, module in enumerate(found[:self.search_limit], 1):
                print(f"  {i:3d}  {module}")
            if len(found) > self.search_limit:
                print(f"\n... {len(found) - self.search_limit} more results not shown")
                print(f"    Set MSF_SEARCH_LIMIT environment variable to show more")
        else:
            print("No modules found matching your query.")
        print()
        
    def do_use(self, arg):
        """Select a module to use"""
        if not arg:
            print("Usage: use <module_path>")
            print("Example: use exploits/linux/http/example")
            return
            
        # Try to find the module
        module_path = self.modules_dir / f"{arg}.py"
        if not module_path.exists():
            # Try without .py extension
            module_path = self.modules_dir / arg
            if module_path.exists() and module_path.is_file():
                pass
            else:
                print(f"Failed to load module: {arg}")
                return
        
        self.current_module = arg
        self.prompt = f'msf6 {arg} > '
        print(f"[*] Using module: {arg}")
        
    def do_info(self, arg):
        """Display information about a module"""
        if not self.current_module:
            print("No module selected. Use 'use <module>' first.")
            return
            
        print(f"\nModule: {self.current_module}")
        print("="*70)
        print("  Description:")
        print("    Python-native exploit module")
        print()
        
    def do_options(self, arg):
        """Display options for the current module"""
        if not self.current_module:
            print("No module selected. Use 'use <module>' first.")
            return
            
        print("\nModule options:\n")
        print("   Name       Current Setting  Required  Description")
        print("   ----       ---------------  --------  -----------")
        print("   RHOST                       yes       The target address")
        print("   RPORT      80               yes       The target port")
        print("   LHOST                       yes       The listen address")
        print("   LPORT      4444             yes       The listen port")
        print()
        
    def do_set(self, arg):
        """Set a module option"""
        if not arg or ' ' not in arg:
            print("Usage: set <option> <value>")
            return
            
        parts = arg.split(None, 1)
        option_name = parts[0]
        option_value = parts[1] if len(parts) > 1 else ''
        
        self.module_options[option_name] = option_value
        print(f"{option_name} => {option_value}")
        
    def do_show(self, arg):
        """Show available modules"""
        if not arg:
            arg = 'all'
            
        if arg == 'exploits':
            print("\nExploits")
            print("="*70)
            exploits_dir = self.modules_dir / 'exploits'
            if exploits_dir.exists():
                count = 0
                for py_file in exploits_dir.rglob('*.py'):
                    if '__init__' not in py_file.name:
                        count += 1
                print(f"  Found {count} exploit modules")
        elif arg == 'auxiliary':
            print("\nAuxiliary Modules")
            print("="*70)
            aux_dir = self.modules_dir / 'auxiliary'
            if aux_dir.exists():
                count = sum(1 for f in aux_dir.rglob('*.py') if '__init__' not in f.name)
                print(f"  Found {count} auxiliary modules")
        else:
            print("\nAvailable module types:")
            print("  exploits")
            print("  auxiliary")
            print("  post")
            print("\nUse 'show <type>' to list modules of that type")
        print()
        
    def do_run(self, arg):
        """Run the current module"""
        if not self.current_module:
            print("No module selected. Use 'use <module>' first.")
            return
            
        print(f"[*] Running module: {self.current_module}")
        print("[!] Module execution not yet fully implemented")
        print("[*] Module options would be:")
        for key, value in self.module_options.items():
            print(f"    {key}: {value}")
        
    def do_back(self, arg):
        """Return to the main prompt"""
        self.current_module = None
        self.module_options = {}
        self.prompt = 'msf6 > '
        
    def do_exit(self, arg):
        """Exit the console"""
        print("\n[*] Exiting...")
        return True
        
    def do_quit(self, arg):
        """Exit the console"""
        return self.do_exit(arg)
        
    def do_EOF(self, arg):
        """Handle Ctrl-D"""
        print()
        return self.do_exit(arg)
        
    def emptyline(self):
        """Do nothing on empty line"""
        pass


def main():
    """Main entry point for msfconsole."""
    parser = argparse.ArgumentParser(
        description='Metasploit Framework Console - Python Native'
    )
    parser.add_argument('-q', '--quiet', action='store_true',
                       help='Suppress banner')
    parser.add_argument('-r', '--resource', type=str,
                       help='Execute resource file')
    parser.add_argument('-x', '--execute-command', type=str,
                       help='Execute the specified console command')
    
    args = parser.parse_args()
    
    # Create and run console
    console = MsfConsole()
    
    if args.quiet:
        console.intro = None
        
    try:
        if args.execute_command:
            console.onecmd(args.execute_command)
        else:
            console.cmdloop()
    except KeyboardInterrupt:
        print("\n[*] Interrupted")
        return


if __name__ == "__main__":
    main()