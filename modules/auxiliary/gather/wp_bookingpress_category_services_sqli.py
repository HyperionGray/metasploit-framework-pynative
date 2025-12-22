#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
Wordpress BookingPress bookingpress_front_get_category_services SQLi

The BookingPress WordPress plugin before 1.0.11 fails to properly sanitize user supplied data
in the `total_service` parameter of the `bookingpress_front_get_category_services` AJAX action
(available to unauthenticated users), prior to using it in a dynamically constructed SQL query.
As a result, unauthenticated attackers can conduct an SQL injection attack to dump sensitive
data from the backend database such as usernames and password hashes.

This module uses this vulnerability to dump the list of WordPress users and their associated
email addresses and password hashes for cracking offline.
"""

import logging
import sys
import os

# Add lib path
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '../../../../lib'))

from metasploit import module
from msf.http_client import HTTPClient, CheckCode

metadata = {
    'name': 'Wordpress BookingPress bookingpress_front_get_category_services SQLi',
    'description': '''
        The BookingPress WordPress plugin before 1.0.11 fails to properly sanitize user supplied data
        in the `total_service` parameter of the `bookingpress_front_get_category_services` AJAX action
        (available to unauthenticated users), prior to using it in a dynamically constructed SQL query.
        As a result, unauthenticated attackers can conduct an SQL injection attack to dump sensitive
        data from the backend database such as usernames and password hashes.
        
        This module uses this vulnerability to dump the list of WordPress users and their associated
        email addresses and password hashes for cracking offline.
    ''',
    'authors': [
        'cydave',
        'destr4ct',
        'jheysel-r7',
    ],
    'date': '2022-02-28',
    'license': 'MSF_LICENSE',
    'type': 'remote_exploit',  # TODO: Adjust type
    'options': {
        'rhost': {'type': 'address', 'description': 'Target address', 'required': True},
        'rport': {'type': 'port', 'description': 'Target port', 'required': True, 'default': 80},
        # TODO: Add module-specific options
    },
    'notes': {
        'stability': ['CRASH_SAFE'],  # TODO: Adjust
        'reliability': ['REPEATABLE_SESSION'],  # TODO: Adjust
        'side_effects': ['IOC_IN_LOGS']  # TODO: Adjust
    }
}


def run(args):
    '''Module entry point.'''
    module.LogHandler.setup(msg_prefix=f"{args['rhost']}:{args['rport']} - ")
    
    rhost = args['rhost']
    rport = args['rport']
    
    logging.info('Starting module execution...')
    
    # TODO: Implement module logic
    # 1. Create HTTP client or TCP socket
    # 2. Check if target is vulnerable
    # 3. Exploit the vulnerability
    # 4. Handle success/failure
    
    try:
        client = HTTPClient(rhost=rhost, rport=rport)
        
        # Your exploit code here
        response = client.get('/')
        if response:
            logging.info(f'Response status: {response.status_code}')
        
        client.close()
        
    except Exception as e:
        logging.error(f'Exploitation failed: {e}')
        return
    
    logging.info('Module execution complete')


if __name__ == '__main__':
    module.run(metadata, run)
