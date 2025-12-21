#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
Villain C2 Server Module

This module launches Villain, a modern interactive shell handler and C2 framework
with a web-based UI for managing reverse shells.

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
    from lib.msf.core.integrations.villain import VillainIntegration
except ImportError:
    dependencies_missing = True


metadata = {
    'name': 'Villain Shell Handler and C2 Server',
    'description': '''
        Launch Villain, a modern C2 framework with web-based UI for managing shells.
        
        Villain provides:
        - Web-based UI for managing multiple shells
        - Multiple shell types (bash, powershell, hoaxshell, etc.)
        - File upload/download capabilities
        - Command execution with output capture
        - Shell upgrade and obfuscation
        - Payload generation
        - Session management
        
        Unlike basic shell catchers, Villain provides a full-featured C2 interface
        that scales well for managing multiple compromised systems.
    ''',
    'authors': [
        'P4x-ng'
    ],
    'date': '2025-12-14',
    'license': 'MSF_LICENSE',
    'references': [
        {'type': 'url', 'ref': 'https://github.com/t3l3machus/Villain'}
    ],
    'type': 'single_scanner',
    'options': {
        'srvhost': {
            'type': 'address',
            'description': 'Server host address',
            'required': True,
            'default': '0.0.0.0'
        },
        'srvport': {
            'type': 'port',
            'description': 'Server port',
            'required': True,
            'default': 6666
        },
        'runtime': {
            'type': 'int',
            'description': 'How long to run server (seconds, 0=forever)',
            'required': False,
            'default': 0
        },
        'villain_path': {
            'type': 'string',
            'description': 'Path to Villain.py (auto-detected if not set)',
            'required': False,
            'default': ''
        }
    },
    'notes': {
        'Stability': ['CRASH_SAFE'],
        'Reliability': ['REPEATABLE_SESSION'],
        'SideEffects': ['IOC_IN_LOGS', 'ARTIFACTS_ON_DISK']
    }
}


def run(args):
    """Execute the Villain server."""
    module.LogHandler.setup(msg_prefix='[Villain] ')
    
    if dependencies_missing:
        logging.error('Module dependencies missing')
        return
    
    srvhost = args.get('srvhost', '0.0.0.0')
    srvport = int(args.get('srvport', 6666))
    runtime = int(args.get('runtime', 0))
    villain_path = args.get('villain_path', '')
    
    logging.info('Starting Villain C2 server')
    
    # Initialize Villain
    config = {}
    if villain_path:
        config['villain_path'] = villain_path
    
    villain = VillainIntegration(config)
    
    success, missing = villain.check_dependencies()
    if not success:
        logging.error(f'Villain dependencies missing: {missing}')
        for msg in missing:
            logging.error(f'  {msg}')
        return
    
    if not villain.initialize():
        logging.error('Failed to initialize Villain')
        return
    
    # Start server
    try:
        result = villain.execute('start', host=srvhost, port=srvport)
        
        if not result.get('success'):
            logging.error(f"Failed to start server: {result.get('error')}")
            return
        
        logging.info(f'Villain server started on {srvhost}:{srvport}')
        logging.info(f'PID: {result.get("pid")}')
        logging.info(f'Web UI: {result.get("web_url")}')
        logging.info('')
        logging.info('Access the web interface to:')
        logging.info('  - Generate payloads')
        logging.info('  - Manage shell sessions')
        logging.info('  - Execute commands')
        logging.info('  - Upload/download files')
        logging.info('')
        
        # Run for specified time or forever
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
        
        logging.info('')
        logging.info('Shutting down server...')
        villain.execute('stop')
    
    finally:
        villain.cleanup()
        logging.info('Villain server stopped')


if __name__ == '__main__':
    module.run(metadata, run)
