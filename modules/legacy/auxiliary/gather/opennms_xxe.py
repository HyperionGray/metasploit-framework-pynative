#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
OpenNMS Authenticated XXE

OpenNMS is vulnerable to XML External Entity Injection in the Real-Time Console interface.
Although this attack requires authentication, there are several factors that increase the
severity of this vulnerability.

1. OpenNMS runs with root privileges, taken from the OpenNMS FAQ: "The difficulty with the
core of OpenNMS is that these components need to run as root to be able to bind to low-numbered
ports or generate network traffic that requires root"

2. The user that you must authenticate as is the "rtc" user which has the default password of
"rtc". There is no mention of this user in the installation guides found here:
http://www.opennms.org/wiki/Tutorial_Installation, only mention that you should change the default
admin password of "admin" for security purposes.
"""

import logging
import sys
import os

# Add lib path
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '../../../../lib'))

from metasploit import module
from msf.http_client import HTTPClient, CheckCode

metadata = {
    'name': 'OpenNMS Authenticated XXE',
    'description': '''
        OpenNMS is vulnerable to XML External Entity Injection in the Real-Time Console interface.
        Although this attack requires authentication, there are several factors that increase the
        severity of this vulnerability.
        
        1. OpenNMS runs with root privileges, taken from the OpenNMS FAQ: "The difficulty with the
        core of OpenNMS is that these components need to run as root to be able to bind to low-numbered
        ports or generate network traffic that requires root"
        
        2. The user that you must authenticate as is the "rtc" user which has the default password of
        "rtc". There is no mention of this user in the installation guides found here:
        http://www.opennms.org/wiki/Tutorial_Installation, only mention that you should change the default
        admin password of "admin" for security purposes.
    ''',
    'date': '2015-01-08',
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
