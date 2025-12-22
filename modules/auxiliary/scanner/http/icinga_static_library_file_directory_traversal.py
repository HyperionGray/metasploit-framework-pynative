#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
Icingaweb Directory Traversal in Static Library File Requests

Icingaweb versions from 2.9.0 to 2.9.5 inclusive, and 2.8.0 to 2.8.5 inclusive suffer from an
unauthenticated directory traversal vulnerability. The vulnerability is triggered
through the icinga-php-thirdparty library, which allows unauthenticated users
to retrieve arbitrary files from the targets filesystem via a GET request to
/lib/icinga/icinga-php-thirdparty/<absolute path to target file on disk> as the user
running the Icingaweb server, which will typically be the www-data user.

This can then be used to retrieve sensitive configuration information from the target
such as the configuration of various services, which may reveal sensitive login
or configuration information, the /etc/passwd file to get a list of valid usernames
for password guessing attacks, or other sensitive files which may exist as part of
additional functionality available on the target server.

This module was tested against Icingaweb 2.9.5 running on Docker.
"""

import logging
import sys
import os

# Add lib path
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '../../../../lib'))

from metasploit import module
from msf.http_client import HTTPClient, CheckCode

metadata = {
    'name': 'Icingaweb Directory Traversal in Static Library File Requests',
    'description': '''
        Icingaweb versions from 2.9.0 to 2.9.5 inclusive, and 2.8.0 to 2.8.5 inclusive suffer from an
        unauthenticated directory traversal vulnerability. The vulnerability is triggered
        through the icinga-php-thirdparty library, which allows unauthenticated users
        to retrieve arbitrary files from the targets filesystem via a GET request to
        /lib/icinga/icinga-php-thirdparty/<absolute path to target file on disk> as the user
        running the Icingaweb server, which will typically be the www-data user.
        
        This can then be used to retrieve sensitive configuration information from the target
        such as the configuration of various services, which may reveal sensitive login
        or configuration information, the /etc/passwd file to get a list of valid usernames
        for password guessing attacks, or other sensitive files which may exist as part of
        additional functionality available on the target server.
        
        This module was tested against Icingaweb 2.9.5 running on Docker.
    ''',
    'authors': [
        'h00die',
        'Jacob Ebben',
        'Thomas Chauchefoin',
    ],
    'date': '2022-05-09',
    'license': 'MSF_LICENSE',
    'type': 'remote_exploit',  # TODO: Adjust type
    'targets': [
        {'name': 'Icingaweb'},  # TODO: Add platform/arch
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
