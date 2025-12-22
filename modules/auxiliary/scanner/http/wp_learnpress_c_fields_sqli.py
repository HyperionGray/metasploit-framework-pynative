#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
WordPress LearnPress Unauthenticated SQLi (CVE-2024-8522, CVE-2024-8529)

The LearnPress WordPress LMS Plugin up to version 4.2.7 is vulnerable to SQL injection via
the 'c_only_fields' and 'c_fields' parameters. This allows unauthenticated attackers to exploit blind SQL injections
and extract sensitive information.
"""

import logging
import sys
import os

# Add lib path
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '../../../../lib'))

from metasploit import module
from msf.http_client import HTTPClient, CheckCode

metadata = {
    'name': 'WordPress LearnPress Unauthenticated SQLi (CVE-2024-8522, CVE-2024-8529)',
    'description': '''
        The LearnPress WordPress LMS Plugin up to version 4.2.7 is vulnerable to SQL injection via
        the 'c_only_fields' and 'c_fields' parameters. This allows unauthenticated attackers to exploit blind SQL injections
        and extract sensitive information.
    ''',
    'authors': [
        'abrahack',
        'Valentin Lobstein',
        'Achref Ben Thameur a.k.a achrefthameur',
    ],
    'date': '2024-09-11',
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
