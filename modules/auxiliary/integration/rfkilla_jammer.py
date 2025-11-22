#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
RF Jamming Module

This module uses the RFKilla integration to perform RF jamming attacks.
Useful for testing wireless security and resilience.

Author: P4x-ng
License: MSF_LICENSE
"""

import logging
import sys
import os

# Add path for framework imports
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.dirname(__file__))))

dependencies_missing = False
try:
    from metasploit import module
    from lib.msf.core.integrations.rfkilla import RFKillaIntegration
except ImportError:
    dependencies_missing = True


metadata = {
    'name': 'RF Jamming via RFKilla',
    'description': '''
        This module provides RF jamming capabilities using the RFKilla tool.
        It can block/unblock wireless devices for testing purposes.
        
        Useful for:
        - Testing wireless resilience
        - Demonstrating RF attacks
        - Security assessments
    ''',
    'authors': [
        'P4x-ng'
    ],
    'date': '2025-11-22',
    'license': 'MSF_LICENSE',
    'references': [
        {'type': 'url', 'ref': 'https://github.com/P4x-ng/rfkilla'}
    ],
    'type': 'single_scanner',
    'options': {
        'action': {
            'type': 'enum',
            'description': 'Action to perform',
            'required': True,
            'default': 'list',
            'values': ['list', 'block', 'unblock']
        },
        'target': {
            'type': 'string',
            'description': 'Target device ID (for block/unblock)',
            'required': False,
            'default': None
        }
    },
    'notes': {
        'Stability': ['CRASH_SAFE'],
        'Reliability': ['REPEATABLE_SESSION'],
        'SideEffects': ['IOC_IN_LOGS', 'PHYSICAL_EFFECTS']
    }
}


def run(args):
    """Execute the RF jamming module."""
    module.LogHandler.setup(msg_prefix='[RFKilla] ')
    
    if dependencies_missing:
        logging.error('Module dependencies missing')
        return
    
    action = args.get('action', 'list')
    target = args.get('target')
    
    logging.info(f'Starting RF operation: {action}')
    
    # Initialize RFKilla
    rfkilla = RFKillaIntegration()
    
    success, missing = rfkilla.check_dependencies()
    if not success:
        logging.error(f'RFKilla dependencies missing: {missing}')
        return
    
    if not rfkilla.initialize():
        logging.error('Failed to initialize RFKilla')
        return
    
    # Execute action
    try:
        result = rfkilla.execute(action, target=target)
        
        if result.get('success'):
            logging.info(f'Action {action} completed successfully')
            
            if action == 'list':
                devices = result.get('devices', [])
                logging.info(f'Found {len(devices)} RF devices:')
                for device in devices:
                    logging.info(f"  - {device.get('name', 'Unknown')}: {device.get('id', 'N/A')}")
            
            elif action in ['block', 'unblock']:
                logging.info(f'Target {target} {action}ed')
        
        else:
            logging.error(f'Action failed: {result.get("error", "Unknown error")}')
    
    finally:
        rfkilla.cleanup()
        logging.info('RF operation completed')


if __name__ == '__main__':
    module.run(metadata, run)
