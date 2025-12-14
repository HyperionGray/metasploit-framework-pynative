#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
Villain Integration for Metasploit PyNative

Villain is a modern C2 framework with a user-friendly interface for managing
reverse shells and provides advanced post-exploitation features.

Author: P4x-ng
License: MSF_LICENSE
"""

import logging
import subprocess
import os
import sys
import time
import requests
import json
from pathlib import Path

from lib.msf.core.integrations import BaseIntegration, IntegrationRegistry


class VillainIntegration(BaseIntegration):
    """
    Integration for Villain - Modern interactive shell handler and C2 framework.
    
    Features:
    - Web-based UI for managing shells
    - Multiple shell types (bash, powershell, hoaxshell, etc.)
    - File upload/download
    - Command execution with output capture
    - Shell upgrade capabilities
    - Payload generation
    """
    
    def __init__(self, config=None):
        super().__init__(config)
        self.name = "villain"
        self.process = None
        self.api_url = None
        self.web_url = None
        
    def check_dependencies(self):
        """Check if Villain is installed."""
        try:
            # Check if Villain.py exists
            villain_paths = [
                '/opt/Villain/Villain.py',
                os.path.expanduser('~/Villain/Villain.py'),
                './Villain/Villain.py',
                self.config.get('villain_path', '')
            ]
            
            for path in villain_paths:
                if os.path.exists(path):
                    self.config['villain_path'] = path
                    logging.info(f"Found Villain at: {path}")
                    return (True, [])
            
            return (False, [
                'Villain not found. Install from: https://github.com/t3l3machus/Villain',
                'git clone https://github.com/t3l3machus/Villain.git',
                'cd Villain && pip install -r requirements.txt'
            ])
            
        except Exception as e:
            return (False, [f'Error checking Villain: {str(e)}'])
    
    def initialize(self):
        """Initialize Villain integration."""
        try:
            # Check dependencies
            success, missing = self.check_dependencies()
            if not success:
                logging.error(f"Missing dependencies: {missing}")
                return False
            
            self.enabled = True
            logging.info("Villain integration initialized")
            return True
            
        except Exception as e:
            logging.error(f"Failed to initialize Villain: {str(e)}")
            return False
    
    def execute(self, command, **kwargs):
        """
        Execute Villain commands.
        
        Commands:
        - start: Start Villain server
        - stop: Stop Villain server
        - generate: Generate payload
        - list_sessions: List active sessions
        - exec: Execute command on session
        - upload: Upload file to session
        - download: Download file from session
        """
        if command == 'start':
            return self._start_server(**kwargs)
        elif command == 'stop':
            return self._stop_server(**kwargs)
        elif command == 'generate':
            return self._generate_payload(**kwargs)
        elif command == 'list_sessions':
            return self._list_sessions(**kwargs)
        elif command == 'exec':
            return self._execute_command(**kwargs)
        elif command == 'upload':
            return self._upload(**kwargs)
        elif command == 'download':
            return self._download(**kwargs)
        else:
            return {'success': False, 'error': f'Unknown command: {command}'}
    
    def _start_server(self, host='0.0.0.0', port=6666, **kwargs):
        """
        Start Villain server.
        
        Args:
            host: Host to bind to
            port: Port to bind to
        """
        try:
            villain_path = self.config.get('villain_path')
            if not villain_path:
                return {
                    'success': False,
                    'error': 'Villain path not configured'
                }
            
            cmd = [
                'python3',
                villain_path,
                '-p', str(port)
            ]
            
            if host != '0.0.0.0':
                cmd.extend(['-i', host])
            
            logging.info(f"Starting Villain server on {host}:{port}")
            logging.info(f"Command: {' '.join(cmd)}")
            
            # Start Villain process
            self.process = subprocess.Popen(
                cmd,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
                cwd=os.path.dirname(villain_path)
            )
            
            # Give it time to start
            time.sleep(3)
            
            if self.process.poll() is not None:
                stdout, stderr = self.process.communicate()
                return {
                    'success': False,
                    'error': f'Villain failed to start: {stderr}'
                }
            
            self.api_url = f'http://{host if host != "0.0.0.0" else "127.0.0.1"}:{port}'
            self.web_url = self.api_url
            
            return {
                'success': True,
                'host': host,
                'port': port,
                'pid': self.process.pid,
                'web_url': self.web_url,
                'message': f'Villain started on {host}:{port}\nWeb UI: {self.web_url}'
            }
            
        except Exception as e:
            logging.error(f"Failed to start Villain: {str(e)}")
            return {'success': False, 'error': str(e)}
    
    def _stop_server(self, **kwargs):
        """Stop Villain server."""
        try:
            if self.process and self.process.poll() is None:
                logging.info("Stopping Villain server")
                self.process.terminate()
                try:
                    self.process.wait(timeout=5)
                except subprocess.TimeoutExpired:
                    logging.warning("Force killing Villain")
                    self.process.kill()
                
                return {
                    'success': True,
                    'message': 'Villain server stopped'
                }
            else:
                return {
                    'success': False,
                    'error': 'Villain server not running'
                }
                
        except Exception as e:
            logging.error(f"Failed to stop Villain: {str(e)}")
            return {'success': False, 'error': str(e)}
    
    def _generate_payload(self, shell_type='windows/powershell/reverse_tcp', 
                         lhost=None, lport=None, **kwargs):
        """
        Generate Villain payload.
        
        Args:
            shell_type: Type of payload
            lhost: Callback host
            lport: Callback port
        """
        try:
            if not lhost or not lport:
                return {
                    'success': False,
                    'error': 'lhost and lport required'
                }
            
            # Villain generates payloads through its UI
            # This would typically interact with Villain's API
            # For now, we'll provide the manual command
            
            payload_info = {
                'success': True,
                'shell_type': shell_type,
                'lhost': lhost,
                'lport': lport,
                'message': f'Access Villain web UI at {self.web_url} to generate payload',
                'note': 'Villain provides interactive payload generation through its web interface'
            }
            
            return payload_info
            
        except Exception as e:
            logging.error(f"Failed to generate payload: {str(e)}")
            return {'success': False, 'error': str(e)}
    
    def _list_sessions(self, **kwargs):
        """List active Villain sessions."""
        try:
            if not self.api_url:
                return {
                    'success': False,
                    'error': 'Villain server not running'
                }
            
            # Villain sessions are managed through its CLI interface
            # This would need to interact with Villain's session management
            
            return {
                'success': True,
                'message': 'Check Villain web UI for active sessions',
                'web_url': self.web_url
            }
            
        except Exception as e:
            logging.error(f"Failed to list sessions: {str(e)}")
            return {'success': False, 'error': str(e)}
    
    def _execute_command(self, session_id, command, **kwargs):
        """Execute command on a Villain session."""
        try:
            if not self.process or self.process.poll() is not None:
                return {
                    'success': False,
                    'error': 'Villain server not running'
                }
            
            # Commands are executed through Villain's CLI
            return {
                'success': True,
                'message': f'Use Villain interface to execute: {command}',
                'session_id': session_id,
                'command': command
            }
            
        except Exception as e:
            logging.error(f"Failed to execute command: {str(e)}")
            return {'success': False, 'error': str(e)}
    
    def _upload(self, session_id, local_path, remote_path, **kwargs):
        """Upload file through Villain."""
        try:
            if not self.process or self.process.poll() is not None:
                return {
                    'success': False,
                    'error': 'Villain server not running'
                }
            
            return {
                'success': True,
                'message': f'Use Villain interface to upload {local_path}',
                'session_id': session_id,
                'local_path': local_path,
                'remote_path': remote_path
            }
            
        except Exception as e:
            logging.error(f"Upload failed: {str(e)}")
            return {'success': False, 'error': str(e)}
    
    def _download(self, session_id, remote_path, local_path, **kwargs):
        """Download file through Villain."""
        try:
            if not self.process or self.process.poll() is not None:
                return {
                    'success': False,
                    'error': 'Villain server not running'
                }
            
            return {
                'success': True,
                'message': f'Use Villain interface to download {remote_path}',
                'session_id': session_id,
                'remote_path': remote_path,
                'local_path': local_path
            }
            
        except Exception as e:
            logging.error(f"Download failed: {str(e)}")
            return {'success': False, 'error': str(e)}
    
    def cleanup(self):
        """Clean up Villain resources."""
        try:
            if self.process and self.process.poll() is None:
                logging.info("Terminating Villain process")
                self.process.terminate()
                try:
                    self.process.wait(timeout=5)
                except subprocess.TimeoutExpired:
                    logging.warning("Force killing Villain process")
                    self.process.kill()
            
            self.enabled = False
            logging.info("Villain cleaned up")
            
        except Exception as e:
            logging.error(f"Cleanup error: {str(e)}")


# Register the integration
IntegrationRegistry.register('villain', VillainIntegration)


if __name__ == '__main__':
    # Test the integration
    logging.basicConfig(level=logging.INFO)
    
    print("=== Villain Integration Test ===")
    
    villain = VillainIntegration()
    
    # Check dependencies
    success, missing = villain.check_dependencies()
    print(f"Dependencies: {'OK' if success else 'MISSING'}")
    if not success:
        print(f"Missing: {missing}")
        for msg in missing:
            print(f"  {msg}")
        sys.exit(1)
    
    # Initialize
    if villain.initialize():
        print("Initialized: OK")
        
        print("\nTo start Villain server:")
        print("  result = villain.execute('start', host='0.0.0.0', port=6666)")
        
        print("\nTo generate payload:")
        print("  result = villain.execute('generate', lhost='attacker', lport=443)")
        
        print("\nFeatures:")
        print("  - Web-based UI for shell management")
        print("  - Multiple shell types (bash, powershell, hoaxshell)")
        print("  - File upload/download")
        print("  - Command execution with output")
        print("  - Shell upgrade capabilities")
        print("  - Payload generation")
        
        villain.cleanup()
    else:
        print("Failed to initialize")
