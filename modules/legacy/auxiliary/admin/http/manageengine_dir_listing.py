#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
ManageEngine Multiple Products Arbitrary Directory Listing

This module exploits a directory listing information disclosure vulnerability in the
FailOverHelperServlet on ManageEngine OpManager, Applications Manager and IT360. It
makes a recursive listing, so it will list the whole drive if you ask it to list / in
Linux or C:\ in Windows. This vulnerability is unauthenticated on OpManager and
Applications Manager, but authenticated in IT360. This module will attempt to login
using the default credentials for the administrator and guest accounts; alternatively
you can provide a pre-authenticated cookie or a username / password combo. For IT360
targets enter the RPORT of the OpManager instance (usually 8300). This module has been
tested on both Windows and Linux with several different versions. Windows paths have to
be escaped with 4 backslashes on the command line. There is a companion module that
allows for arbitrary file download. This vulnerability has been fixed in Applications
Manager v11.9 b11912 and OpManager 11.6.
"""

import logging
import sys
import os

# Add lib path
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '../../../../lib'))

from metasploit import module
from msf.http_client import HTTPClient, CheckCode

metadata = {
    'name': 'ManageEngine Multiple Products Arbitrary Directory Listing',
    'description': '''
        This module exploits a directory listing information disclosure vulnerability in the
        FailOverHelperServlet on ManageEngine OpManager, Applications Manager and IT360. It
        makes a recursive listing, so it will list the whole drive if you ask it to list / in
        Linux or C:\ in Windows. This vulnerability is unauthenticated on OpManager and
        Applications Manager, but authenticated in IT360. This module will attempt to login
        using the default credentials for the administrator and guest accounts; alternatively
        you can provide a pre-authenticated cookie or a username / password combo. For IT360
        targets enter the RPORT of the OpManager instance (usually 8300). This module has been
        tested on both Windows and Linux with several different versions. Windows paths have to
        be escaped with 4 backslashes on the command line. There is a companion module that
        allows for arbitrary file download. This vulnerability has been fixed in Applications
        Manager v11.9 b11912 and OpManager 11.6.
    ''',
    'date': '2015-01-28',
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
