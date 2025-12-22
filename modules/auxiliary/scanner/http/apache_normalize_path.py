#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
Apache 2.4.49/2.4.50 Traversal RCE scanner

This module scans for an unauthenticated RCE vulnerability which exists in Apache version 2.4.49 (CVE-2021-41773).
If files outside of the document root are not protected by 'require all denied' and CGI has been explicitly enabled,
it can be used to execute arbitrary commands (Remote Command Execution).
This vulnerability has been reintroduced in Apache 2.4.50 fix (CVE-2021-42013).
"""

import logging
import sys
import os

# Add lib path
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '../../../../lib'))

from metasploit import module
from msf.http_client import HTTPClient, CheckCode

metadata = {
    'name': 'Apache 2.4.49/2.4.50 Traversal RCE scanner',
    'description': '''
        This module scans for an unauthenticated RCE vulnerability which exists in Apache version 2.4.49 (CVE-2021-41773).
        If files outside of the document root are not protected by 'require all denied' and CGI has been explicitly enabled,
        it can be used to execute arbitrary commands (Remote Command Execution).
        This vulnerability has been reintroduced in Apache 2.4.50 fix (CVE-2021-42013).
    ''',
    'authors': [
        'Ash Daulton',
        'Dhiraj Mishra',
        'mekhalleh (RAMELLA Sébastien)',
    ],
    'date': '2021-05-10',
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
