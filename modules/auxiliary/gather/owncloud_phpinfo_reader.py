#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
ownCloud Phpinfo Reader

Docker containers of ownCloud compiled after February 2023, which have version 0.2.0 before 0.2.1 or 0.3.0 before 0.3.1 of the app `graph` installed
contain a test file which prints `phpinfo()` to an unauthenticated user. A post file name must be appended to the URL to bypass the login filter.
Docker may export sensitive environment variables including ownCloud, DB, redis, SMTP, and S3 credentials, as well as other host information.
"""

import logging
import sys
import os

# Add lib path
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '../../../../lib'))

from metasploit import module
from msf.http_client import HTTPClient, CheckCode

metadata = {
    'name': 'ownCloud Phpinfo Reader',
    'description': '''
        Docker containers of ownCloud compiled after February 2023, which have version 0.2.0 before 0.2.1 or 0.3.0 before 0.3.1 of the app `graph` installed
        contain a test file which prints `phpinfo()` to an unauthenticated user. A post file name must be appended to the URL to bypass the login filter.
        Docker may export sensitive environment variables including ownCloud, DB, redis, SMTP, and S3 credentials, as well as other host information.
    ''',
    'authors': [
        'h00die',
        'creacitysec',
        'Ron Bowes',
        'random-robbie',
        'Christian Fischer',
    ],
    'date': '2023-11-21',
    'license': 'MSF_LICENSE',
    'type': 'remote_exploit',  # TODO: Adjust type
    'targets': [
        {'name': 'Automatic Target'},  # TODO: Add platform/arch
    ],
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
