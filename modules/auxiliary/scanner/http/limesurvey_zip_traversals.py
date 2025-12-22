#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
LimeSurvey Zip Path Traversals

This module exploits an authenticated path traversal vulnerability found in LimeSurvey
versions between 4.0 and 4.1.11 with CVE-2020-11455 or <= 3.15.9 with CVE-2019-9960,
inclusive.
In CVE-2020-11455 the getZipFile function within the filemanager functionality
allows for arbitrary file download.  The file retrieved may be deleted after viewing,
which was confirmed in testing.
In CVE-2019-9960 the szip function within the downloadZip functionality allows
for arbitrary file download.
Verified against 4.1.11-200316, 3.15.0-181008, 3.9.0-180604, 3.6.0-180328,
3.0.0-171222, and 2.70.0-170921.
"""

import logging
import sys
import os

# Add lib path
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '../../../../lib'))

from metasploit import module
from msf.http_client import HTTPClient, CheckCode

metadata = {
    'name': 'LimeSurvey Zip Path Traversals',
    'description': '''
        This module exploits an authenticated path traversal vulnerability found in LimeSurvey
        versions between 4.0 and 4.1.11 with CVE-2020-11455 or <= 3.15.9 with CVE-2019-9960,
        inclusive.
        In CVE-2020-11455 the getZipFile function within the filemanager functionality
        allows for arbitrary file download.  The file retrieved may be deleted after viewing,
        which was confirmed in testing.
        In CVE-2019-9960 the szip function within the downloadZip functionality allows
        for arbitrary file download.
        Verified against 4.1.11-200316, 3.15.0-181008, 3.9.0-180604, 3.6.0-180328,
        3.0.0-171222, and 2.70.0-170921.
    ''',
    'authors': [
        'h00die',
        'Matthew Aberegg',
        'Michael Burkey',
        'Federico Fernandez',
        'Alejandro Parodi',
    ],
    'date': '2020-04-02',
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
