#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
GitLab Authenticated File Read

GitLab version 16.0 contains a directory traversal for arbitrary file read
as the `gitlab-www` user. This module requires authentication for exploitation.
In order to use this module, a user must be able to create a project and groups.
When exploiting this vulnerability, there is a direct correlation between the traversal
depth, and the depth of groups the vulnerable project is in. The minimum for this seems
to be 5, but up to 11 have also been observed. An example of this, is if the directory
traversal needs a depth of 11, a group
and 10 nested child groups, each a sub of the previous, will be created (adding up to 11).
Visually this looks like:
Group1->sub1->sub2->sub3->sub4->sub5->sub6->sub7->sub8->sub9->sub10.
If the depth was 5, a group and 4 nested child groups would be created.
With all these requirements satisfied a dummy file is uploaded, and the full
traversal is then executed. Cleanup is performed by deleting the first group which
cascades to deleting all other objects created.
"""

import logging
import sys
import os

# Add lib path
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '../../../../lib'))

from metasploit import module
from msf.http_client import HTTPClient, CheckCode

metadata = {
    'name': 'GitLab Authenticated File Read',
    'description': '''
        GitLab version 16.0 contains a directory traversal for arbitrary file read
        as the `gitlab-www` user. This module requires authentication for exploitation.
        In order to use this module, a user must be able to create a project and groups.
        When exploiting this vulnerability, there is a direct correlation between the traversal
        depth, and the depth of groups the vulnerable project is in. The minimum for this seems
        to be 5, but up to 11 have also been observed. An example of this, is if the directory
        traversal needs a depth of 11, a group
        and 10 nested child groups, each a sub of the previous, will be created (adding up to 11).
        Visually this looks like:
        Group1->sub1->sub2->sub3->sub4->sub5->sub6->sub7->sub8->sub9->sub10.
        If the depth was 5, a group and 4 nested child groups would be created.
        With all these requirements satisfied a dummy file is uploaded, and the full
        traversal is then executed. Cleanup is performed by deleting the first group which
        cascades to deleting all other objects created.
    ''',
    'authors': [
        'h00die',
        'pwnie',
        'Vitellozzo',
    ],
    'date': '2023-05-23',
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
