#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
Sliver C2 Framework Integration Module

This module provides integration with Sliver, a modern open-source C2 framework
with advanced features for red team operations and adversary simulations.

Author: P4x-ng
License: MSF_LICENSE
"""

import logging
import sys
import os
import time

# Add path for framework imports
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.dirname(__file__))))

dependencies_missing = False
try:
    from metasploit import module
    from lib.msf.core.integrations.sliver import SliverIntegration
except ImportError:
    dependencies_missing = True


metadata = {
    'name': 'Sliver C2 Framework Server',
    'description': '''
        Launch and manage Sliver C2 framework for advanced red team operations.
        
        Sliver is a modern, open-source C2 framework that provides:
        - Dynamic code generation (Go, C#, shellcode, service binaries)
        - Secure C2 over mTLS, WireGuard, HTTP(S), and DNS
        - Process injection and migration techniques
        - In-memory .NET assembly execution
        - Windows token manipulation and impersonation
        - Advanced tunneling and port forwarding
        - Session multiplexing for efficiency
        - Anti-forensics features
        - Cross-platform support (Windows, Linux, macOS)
        
        Sliver represents the next generation of C2 frameworks with a focus on
        operational security, stability, and advanced post-exploitation capabilities.
    ''',
    'authors': [
        'P4x-ng'
    ],
    'date': '2025-12-14',
    'license': 'MSF_LICENSE',
    'references': [
        {'type': 'url', 'ref': 'https://github.com/BishopFox/sliver'},
        {'type': 'url', 'ref': 'https://sliver.sh/'},
        {'type': 'url', 'ref': 'https://sliver.sh/docs'}
    ],
    'type': 'single_scanner',
    'options': {
        'action': {
            'type': 'enum',
            'description': 'Action to perform',
            'required': True,
            'default': 'start_server',
            'values': ['start_server', 'generate', 'start_listener']
        },
        'daemon': {
            'type': 'bool',
            'description': 'Run server as daemon',
            'required': False,
            'default': True
        },
        'listener_protocol': {
            'type': 'enum',
            'description': 'Listener protocol',
            'required': False,
            'default': 'mtls',
            'values': ['mtls', 'wg', 'http', 'https', 'dns']
        },
        'lhost': {
            'type': 'address',
            'description': 'Listener host',
            'required': False,
            'default': '0.0.0.0'
        },
        'lport': {
            'type': 'port',
            'description': 'Listener port',
            'required': False,
            'default': 8888
        },
        'implant_os': {
            'type': 'enum',
            'description': 'Implant target OS',
            'required': False,
            'default': 'windows',
            'values': ['windows', 'linux', 'macos']
        },
        'implant_arch': {
            'type': 'enum',
            'description': 'Implant architecture',
            'required': False,
            'default': 'amd64',
            'values': ['amd64', '386', 'arm', 'arm64']
        },
        'implant_format': {
            'type': 'enum',
            'description': 'Implant output format',
            'required': False,
            'default': 'exe',
            'values': ['exe', 'shared', 'shellcode', 'service']
        },
        'output_path': {
            'type': 'string',
            'description': 'Output path for generated implant',
            'required': False,
            'default': ''
        },
        'runtime': {
            'type': 'int',
            'description': 'How long to run (seconds, 0=forever)',
            'required': False,
            'default': 0
        }
    },
    'notes': {
        'Stability': ['CRASH_SAFE'],
        'Reliability': ['REPEATABLE_SESSION'],
        'SideEffects': ['IOC_IN_LOGS', 'ARTIFACTS_ON_DISK', 'CONFIG_CHANGES']
    }
}


def run(args):
    """Execute Sliver C2 operations."""
    module.LogHandler.setup(msg_prefix='[Sliver] ')
    
    if dependencies_missing:
        logging.error('Module dependencies missing')
        return
    
    action = args.get('action', 'start_server')
    daemon = args.get('daemon', True)
    listener_protocol = args.get('listener_protocol', 'mtls')
    lhost = args.get('lhost', '0.0.0.0')
    lport = int(args.get('lport', 8888))
    implant_os = args.get('implant_os', 'windows')
    implant_arch = args.get('implant_arch', 'amd64')
    implant_format = args.get('implant_format', 'exe')
    output_path = args.get('output_path', '')
    runtime = int(args.get('runtime', 0))
    
    logging.info('Initializing Sliver C2 Framework')
    
    sliver = SliverIntegration()
    
    success, missing = sliver.check_dependencies()
    if not success:
        logging.error(f'Sliver dependencies missing: {missing}')
        for msg in missing:
            logging.error(f'  {msg}')
        return
    
    if not sliver.initialize():
        logging.error('Failed to initialize Sliver')
        return
    
    try:
        if action == 'start_server':
            logging.info('Starting Sliver server...')
            result = sliver.execute('start_server', daemon=daemon)
            
            if not result.get('success'):
                logging.error(f"Failed to start server: {result.get('error')}")
                return
            
            logging.info(f'Sliver server started (PID: {result.get("pid")})')
            logging.info('Server is ready for client connections')
            logging.info('')
            logging.info('Next steps:')
            logging.info('  1. Start a listener using action=start_listener')
            logging.info('  2. Generate an implant using action=generate')
            logging.info('  3. Execute the implant on target systems')
            logging.info('  4. Use sliver-client to interact with sessions')
            
        elif action == 'start_listener':
            logging.info(f'Starting {listener_protocol.upper()} listener...')
            result = sliver.execute(
                'start_listener',
                protocol=listener_protocol,
                host=lhost,
                port=lport,
                persistent=True
            )
            
            if not result.get('success'):
                logging.error(f"Failed to start listener: {result.get('error')}")
                return
            
            logging.info(f'Listener started on {lhost}:{lport}')
            logging.info(f'Protocol: {listener_protocol.upper()}')
            logging.info('Listener is persistent and will survive restarts')
            
        elif action == 'generate':
            logging.info('Generating Sliver implant...')
            
            if not output_path:
                output_path = f'/tmp/sliver_{implant_os}_{implant_arch}.{implant_format}'
            
            result = sliver.execute(
                'generate',
                os=implant_os,
                arch=implant_arch,
                format=implant_format,
                mtls_host=lhost if listener_protocol == 'mtls' else None,
                mtls_port=lport if listener_protocol == 'mtls' else None,
                http_host=lhost if listener_protocol in ['http', 'https'] else None,
                http_port=lport if listener_protocol in ['http', 'https'] else None,
                output=output_path
            )
            
            if not result.get('success'):
                logging.error(f"Failed to generate implant: {result.get('error')}")
                return
            
            logging.info(f'Implant generated successfully')
            logging.info(f'Output: {output_path}')
            logging.info(f'OS: {implant_os}, Arch: {implant_arch}, Format: {implant_format}')
        
        # Run for specified time if needed
        if runtime > 0 and action == 'start_server':
            logging.info(f'Running for {runtime} seconds...')
            time.sleep(runtime)
        elif runtime == 0 and action == 'start_server':
            logging.info('Running until interrupted (Ctrl+C)...')
            try:
                while True:
                    time.sleep(1)
            except KeyboardInterrupt:
                logging.info('Interrupted by user')
    
    finally:
        if action == 'start_server':
            logging.info('Shutting down Sliver server...')
        sliver.cleanup()
        logging.info('Sliver operations complete')


if __name__ == '__main__':
    module.run(metadata, run)
