#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
Havoc C2 Integration for Metasploit PyNative

Havoc is a modern, open-source post-exploitation command and control framework
with advanced features for red team operations.

Author: P4x-ng
License: MSF_LICENSE
"""

import logging
import subprocess
import os
import sys
import time
import json
import socket
from pathlib import Path

from lib.msf.core.integrations import BaseIntegration, IntegrationRegistry


class HavocIntegration(BaseIntegration):
    """
    Integration for Havoc C2 Framework.
    
    Features:
    - Modern C2 with GUI teamserver
    - Sleep obfuscation techniques
    - Indirect syscalls for evasion
    - Advanced injection techniques
    - Token manipulation
    - Credential dumping
    - Lateral movement capabilities
    - Python/BOF extension support
    """
    
    def __init__(self, config=None):
        super().__init__(config)
        self.name = "havoc"
        self.teamserver_process = None
        self.client_process = None
        self.teamserver_host = None
        self.teamserver_port = None
        
    def check_dependencies(self):
        """Check if Havoc is installed."""
        try:
            # Check for Havoc in common locations
            havoc_paths = [
                '/opt/Havoc/havoc',
                os.path.expanduser('~/Havoc/havoc'),
                './Havoc/havoc',
                self.config.get('havoc_path', '')
            ]
            
            for path in havoc_paths:
                if os.path.exists(path):
                    self.config['havoc_path'] = os.path.dirname(path)
                    logging.info(f"Found Havoc at: {path}")
                    return (True, [])
            
            return (False, [
                'Havoc not found.',
                'Install from: https://github.com/HavocFramework/Havoc',
                'git clone https://github.com/HavocFramework/Havoc.git',
                'Follow build instructions in Havoc/INSTALL.md'
            ])
            
        except Exception as e:
            return (False, [f'Error checking Havoc: {str(e)}'])
    
    def initialize(self):
        """Initialize Havoc integration."""
        try:
            # Check dependencies
            success, missing = self.check_dependencies()
            if not success:
                logging.error(f"Missing dependencies: {missing}")
                return False
            
            self.enabled = True
            logging.info("Havoc integration initialized")
            return True
            
        except Exception as e:
            logging.error(f"Failed to initialize Havoc: {str(e)}")
            return False
    
    def execute(self, command, **kwargs):
        """
        Execute Havoc commands.
        
        Commands:
        - start_teamserver: Start Havoc teamserver
        - stop_teamserver: Stop teamserver
        - start_client: Start Havoc client
        - generate: Generate demon agent
        - list_listeners: List active listeners
        - add_listener: Add new listener
        - list_sessions: List active sessions
        - execute: Execute command on session
        """
        if command == 'start_teamserver':
            return self._start_teamserver(**kwargs)
        elif command == 'stop_teamserver':
            return self._stop_teamserver(**kwargs)
        elif command == 'start_client':
            return self._start_client(**kwargs)
        elif command == 'generate':
            return self._generate_agent(**kwargs)
        elif command == 'list_listeners':
            return self._list_listeners(**kwargs)
        elif command == 'add_listener':
            return self._add_listener(**kwargs)
        elif command == 'list_sessions':
            return self._list_sessions(**kwargs)
        elif command == 'execute':
            return self._execute_command(**kwargs)
        else:
            return {'success': False, 'error': f'Unknown command: {command}'}
    
    def _start_teamserver(self, host='0.0.0.0', port=40056, 
                         password=None, profile=None, **kwargs):
        """
        Start Havoc teamserver.
        
        Args:
            host: Teamserver host
            port: Teamserver port
            password: Teamserver password
            profile: Path to teamserver profile (YAML)
        """
        try:
            havoc_path = self.config.get('havoc_path')
            if not havoc_path:
                return {
                    'success': False,
                    'error': 'Havoc path not configured'
                }
            
            teamserver_bin = os.path.join(havoc_path, 'teamserver')
            if not os.path.exists(teamserver_bin):
                return {
                    'success': False,
                    'error': f'Teamserver binary not found at {teamserver_bin}'
                }
            
            # Create default profile if not provided
            if not profile:
                profile = self._create_default_profile()
            
            cmd = [
                teamserver_bin,
                '--profile', profile
            ]
            
            if host and host != '0.0.0.0':
                cmd.extend(['--host', host])
            
            if port:
                cmd.extend(['--port', str(port)])
            
            logging.info(f"Starting Havoc teamserver on {host}:{port}")
            logging.info(f"Command: {' '.join(cmd)}")
            
            # Start teamserver
            self.teamserver_process = subprocess.Popen(
                cmd,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
                cwd=havoc_path
            )
            
            # Give it time to start
            time.sleep(3)
            
            if self.teamserver_process.poll() is not None:
                stdout, stderr = self.teamserver_process.communicate()
                return {
                    'success': False,
                    'error': f'Teamserver failed to start: {stderr}'
                }
            
            self.teamserver_host = host
            self.teamserver_port = port
            
            return {
                'success': True,
                'host': host,
                'port': port,
                'pid': self.teamserver_process.pid,
                'profile': profile,
                'message': f'Havoc teamserver started on {host}:{port}'
            }
            
        except Exception as e:
            logging.error(f"Failed to start teamserver: {str(e)}")
            return {'success': False, 'error': str(e)}
    
    def _stop_teamserver(self, **kwargs):
        """Stop Havoc teamserver."""
        try:
            if self.teamserver_process and self.teamserver_process.poll() is None:
                logging.info("Stopping Havoc teamserver")
                self.teamserver_process.terminate()
                try:
                    self.teamserver_process.wait(timeout=5)
                except subprocess.TimeoutExpired:
                    logging.warning("Force killing Havoc teamserver")
                    self.teamserver_process.kill()
                
                return {
                    'success': True,
                    'message': 'Havoc teamserver stopped'
                }
            else:
                return {
                    'success': False,
                    'error': 'Havoc teamserver not running'
                }
                
        except Exception as e:
            logging.error(f"Failed to stop teamserver: {str(e)}")
            return {'success': False, 'error': str(e)}
    
    def _start_client(self, **kwargs):
        """Start Havoc client GUI."""
        try:
            havoc_path = self.config.get('havoc_path')
            if not havoc_path:
                return {
                    'success': False,
                    'error': 'Havoc path not configured'
                }
            
            client_bin = os.path.join(havoc_path, 'havoc')
            if not os.path.exists(client_bin):
                return {
                    'success': False,
                    'error': f'Client binary not found at {client_bin}'
                }
            
            logging.info("Starting Havoc client")
            
            self.client_process = subprocess.Popen(
                [client_bin],
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                cwd=havoc_path
            )
            
            time.sleep(2)
            
            return {
                'success': True,
                'pid': self.client_process.pid,
                'message': 'Havoc client started'
            }
            
        except Exception as e:
            logging.error(f"Failed to start client: {str(e)}")
            return {'success': False, 'error': str(e)}
    
    def _create_default_profile(self):
        """Create a default Havoc teamserver profile."""
        import tempfile
        
        # Create temp file with secure permissions (0o600)
        fd, profile_path = tempfile.mkstemp(suffix='.yaml', prefix='havoc_profile_')
        
        # Basic Havoc profile
        profile_content = """
Teamserver:
  Host: "0.0.0.0"
  Port: 40056

Operators:
  - Name: "operator"
    Password: "password"

Listeners:
  - Name: "HTTP Listener"
    Protocol: "HTTP"
    Hosts:
      - "0.0.0.0"
    Port: 80
    HostBind: "0.0.0.0"
    HostRotation: "round-robin"
"""
        
        # Set secure permissions before writing
        os.chmod(profile_path, 0o600)
        
        with os.fdopen(fd, 'w') as f:
            f.write(profile_content)
        
        return profile_path
    
    def _generate_agent(self, listener='HTTP Listener', arch='x64',
                       format='Windows Exe', output=None, **kwargs):
        """
        Generate Havoc demon agent.
        
        Args:
            listener: Listener name to use
            arch: Architecture (x64, x86)
            format: Output format
            output: Output file path
        """
        try:
            # Havoc agents are typically generated through the GUI
            # This would require API integration with the teamserver
            
            return {
                'success': True,
                'listener': listener,
                'arch': arch,
                'format': format,
                'output': output,
                'message': 'Use Havoc client GUI to generate demon agent',
                'note': 'Havoc provides interactive agent generation through its GUI'
            }
            
        except Exception as e:
            logging.error(f"Failed to generate agent: {str(e)}")
            return {'success': False, 'error': str(e)}
    
    def _list_listeners(self, **kwargs):
        """List active Havoc listeners."""
        try:
            # This would require API integration
            return {
                'success': True,
                'message': 'Use Havoc client GUI to view listeners',
                'note': 'Listeners are managed through the Havoc GUI'
            }
            
        except Exception as e:
            logging.error(f"Failed to list listeners: {str(e)}")
            return {'success': False, 'error': str(e)}
    
    def _add_listener(self, name, protocol='HTTP', host='0.0.0.0', 
                     port=80, **kwargs):
        """Add new Havoc listener."""
        try:
            # This would require API integration
            return {
                'success': True,
                'name': name,
                'protocol': protocol,
                'host': host,
                'port': port,
                'message': 'Use Havoc client GUI to add listener',
                'note': 'Listeners are managed through the Havoc GUI'
            }
            
        except Exception as e:
            logging.error(f"Failed to add listener: {str(e)}")
            return {'success': False, 'error': str(e)}
    
    def _list_sessions(self, **kwargs):
        """List active Havoc sessions."""
        try:
            # This would require API integration
            return {
                'success': True,
                'message': 'Use Havoc client GUI to view sessions',
                'note': 'Sessions are managed through the Havoc GUI'
            }
            
        except Exception as e:
            logging.error(f"Failed to list sessions: {str(e)}")
            return {'success': False, 'error': str(e)}
    
    def _execute_command(self, session_id, command, **kwargs):
        """Execute command on Havoc session."""
        try:
            # This would require API integration
            return {
                'success': True,
                'session_id': session_id,
                'command': command,
                'message': 'Use Havoc client GUI to execute commands',
                'note': 'Commands are executed through the Havoc GUI'
            }
            
        except Exception as e:
            logging.error(f"Failed to execute command: {str(e)}")
            return {'success': False, 'error': str(e)}
    
    def cleanup(self):
        """Clean up Havoc resources."""
        try:
            # Stop teamserver if running
            if self.teamserver_process and self.teamserver_process.poll() is None:
                logging.info("Terminating Havoc teamserver")
                self.teamserver_process.terminate()
                try:
                    self.teamserver_process.wait(timeout=5)
                except subprocess.TimeoutExpired:
                    logging.warning("Force killing Havoc teamserver")
                    self.teamserver_process.kill()
            
            # Stop client if running
            if self.client_process and self.client_process.poll() is None:
                logging.info("Terminating Havoc client")
                self.client_process.terminate()
                try:
                    self.client_process.wait(timeout=5)
                except subprocess.TimeoutExpired:
                    logging.warning("Force killing Havoc client")
                    self.client_process.kill()
            
            self.enabled = False
            logging.info("Havoc cleaned up")
            
        except Exception as e:
            logging.error(f"Cleanup error: {str(e)}")


# Register the integration
IntegrationRegistry.register('havoc', HavocIntegration)


if __name__ == '__main__':
    # Test the integration
    logging.basicConfig(level=logging.INFO)
    
    print("=== Havoc C2 Integration Test ===")
    
    havoc = HavocIntegration()
    
    # Check dependencies
    success, missing = havoc.check_dependencies()
    print(f"Dependencies: {'OK' if success else 'MISSING'}")
    if not success:
        print(f"Missing: {missing}")
        for msg in missing:
            print(f"  {msg}")
        sys.exit(1)
    
    # Initialize
    if havoc.initialize():
        print("Initialized: OK")
        
        print("\nTo start Havoc teamserver:")
        print("  result = havoc.execute('start_teamserver', port=40056)")
        
        print("\nTo start Havoc client:")
        print("  result = havoc.execute('start_client')")
        
        print("\nTo generate agent:")
        print("  result = havoc.execute('generate', listener='HTTP Listener', output='demon.exe')")
        
        print("\nFeatures:")
        print("  - Modern C2 with GUI teamserver")
        print("  - Sleep obfuscation techniques")
        print("  - Indirect syscalls for evasion")
        print("  - Advanced injection techniques")
        print("  - Token manipulation")
        print("  - Credential dumping")
        print("  - Lateral movement capabilities")
        print("  - Python/BOF extension support")
        
        havoc.cleanup()
    else:
        print("Failed to initialize")
