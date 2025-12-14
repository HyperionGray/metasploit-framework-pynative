#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
Havoc C2 Framework Integration Module

This module provides integration with Havoc, a modern post-exploitation
command and control framework with advanced features for red team operations.

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
    from lib.msf.core.integrations.havoc import HavocIntegration
except ImportError:
    dependencies_missing = True


metadata = {
    'name': 'Havoc C2 Framework Server',
    'description': '''
        Launch and manage Havoc C2 framework for advanced red team operations.
        
        Havoc is a modern, open-source post-exploitation C2 framework that provides:
        - Modern GUI teamserver for collaborative operations
        - Sleep obfuscation techniques for stealth
        - Indirect syscalls for AV/EDR evasion
        - Advanced injection techniques (process hollowing, thread hijacking)
        - Windows token manipulation and impersonation
        - Credential dumping and harvesting
        - Lateral movement capabilities
        - Python and BOF (Beacon Object Files) extension support
        - Multiple C2 profiles for customization
        - Cross-platform demon agents
        
        Havoc represents a modern approach to C2 with a focus on usability,
        stealth, and extensibility for professional red team engagements.
    ''',
    'authors': [
        'P4x-ng'
    ],
    'date': '2025-12-14',
    'license': 'MSF_LICENSE',
    'references': [
        {'type': 'url', 'ref': 'https://github.com/HavocFramework/Havoc'},
        {'type': 'url', 'ref': 'https://havocframework.com/'}
    ],
    'type': 'single_scanner',
    'options': {
        'action': {
            'type': 'enum',
            'description': 'Action to perform',
            'required': True,
            'default': 'start_teamserver',
            'values': ['start_teamserver', 'start_client']
        },
        'srvhost': {
            'type': 'address',
            'description': 'Teamserver host',
            'required': False,
            'default': '0.0.0.0'
        },
        'srvport': {
            'type': 'port',
            'description': 'Teamserver port',
            'required': False,
            'default': 40056
        },
        'password': {
            'type': 'string',
            'description': 'Teamserver password',
            'required': False,
            'default': ''
        },
        'profile_path': {
            'type': 'string',
            'description': 'Path to teamserver profile YAML',
            'required': False,
            'default': ''
        },
        'havoc_path': {
            'type': 'string',
            'description': 'Path to Havoc installation (auto-detected if not set)',
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
    """Execute Havoc C2 operations."""
    module.LogHandler.setup(msg_prefix='[Havoc] ')
    
    if dependencies_missing:
        logging.error('Module dependencies missing')
        return
    
    action = args.get('action', 'start_teamserver')
    srvhost = args.get('srvhost', '0.0.0.0')
    srvport = int(args.get('srvport', 40056))
    password = args.get('password', '')
    profile_path = args.get('profile_path', '')
    havoc_path = args.get('havoc_path', '')
    runtime = int(args.get('runtime', 0))
    
    logging.info('Initializing Havoc C2 Framework')
    
    config = {}
    if havoc_path:
        config['havoc_path'] = havoc_path
    
    havoc = HavocIntegration(config)
    
    success, missing = havoc.check_dependencies()
    if not success:
        logging.error(f'Havoc dependencies missing: {missing}')
        for msg in missing:
            logging.error(f'  {msg}')
        return
    
    if not havoc.initialize():
        logging.error('Failed to initialize Havoc')
        return
    
    try:
        if action == 'start_teamserver':
            logging.info('Starting Havoc teamserver...')
            
            kwargs = {
                'host': srvhost,
                'port': srvport
            }
            
            if password:
                kwargs['password'] = password
            
            if profile_path:
                kwargs['profile'] = profile_path
            
            result = havoc.execute('start_teamserver', **kwargs)
            
            if not result.get('success'):
                logging.error(f"Failed to start teamserver: {result.get('error')}")
                return
            
            logging.info(f'Havoc teamserver started on {srvhost}:{srvport}')
            logging.info(f'PID: {result.get("pid")}')
            logging.info(f'Profile: {result.get("profile")}')
            logging.info('')
            logging.info('Next steps:')
            logging.info('  1. Run with action=start_client to launch GUI client')
            logging.info('  2. Connect client to teamserver')
            logging.info('  3. Generate demon agents from client interface')
            logging.info('  4. Deploy agents and manage sessions through GUI')
            logging.info('')
            logging.info('Features available through GUI:')
            logging.info('  - Generate demon agents for multiple platforms')
            logging.info('  - Manage listeners (HTTP, HTTPS, SMB, TCP, etc.)')
            logging.info('  - Execute commands on compromised systems')
            logging.info('  - Credential dumping and token manipulation')
            logging.info('  - Lateral movement tools')
            logging.info('  - File upload/download')
            logging.info('  - Process injection and migration')
            
            # Run for specified time if needed
            if runtime > 0:
                logging.info(f'Running for {runtime} seconds...')
                time.sleep(runtime)
            else:
                logging.info('Running until interrupted (Ctrl+C)...')
                try:
                    while True:
                        time.sleep(1)
                except KeyboardInterrupt:
                    logging.info('Interrupted by user')
            
        elif action == 'start_client':
            logging.info('Starting Havoc client GUI...')
            
            result = havoc.execute('start_client')
            
            if not result.get('success'):
                logging.error(f"Failed to start client: {result.get('error')}")
                return
            
            logging.info(f'Havoc client started (PID: {result.get("pid")})')
            logging.info('GUI should be visible now')
            logging.info('Use the GUI to connect to the teamserver and manage operations')
            
            # Keep running while client is active
            logging.info('Client running... Press Ctrl+C to stop')
            try:
                while True:
                    time.sleep(1)
            except KeyboardInterrupt:
                logging.info('Interrupted by user')
    
    finally:
        logging.info('Shutting down Havoc...')
        havoc.cleanup()
        logging.info('Havoc operations complete')


if __name__ == '__main__':
    module.run(metadata, run)
