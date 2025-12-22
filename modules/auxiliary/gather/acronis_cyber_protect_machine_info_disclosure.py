#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
Acronis Cyber Protect/Backup machine info disclosure

Acronis Cyber Protect or Backup is an enterprise backup/recovery solution for all,
compute, storage and application resources. Businesses and Service Providers are using it
to protect and backup all IT assets in their IT environment.
This module exploits an authentication bypass vulnerability at the Acronis Cyber Protect
appliance which, in its default configuration, allows the anonymous registration of new
backup/protection agents on new endpoints. This API endpoint also generates bearer tokens
which the agent then uses to authenticate to the appliance.
As the management web console is running on the same port as the API for the agents, this
bearer token is also valid for any actions on the web console. This allows an attacker
with network access to the appliance to start the registration of a new agent, retrieve
a bearer token that provides admin access to the available functions in the web console.

This module will gather all machine info (endpoints) configured and managed by the appliance.
This information can be used in a subsequent attack that exploits this vulnerability to
execute arbitrary commands on both the managed endpoint and the appliance.
This exploit is covered in another module `exploit/multi/acronis_cyber_protect_unauth_rce_cve_2022_3405`.

Acronis Cyber Protect 15 (Windows, Linux) before build 29486 and
Acronis Cyber Backup 12.5 (Windows, Linux) before build 16545 are vulnerable.
"""

import logging
import sys
import os

# Add lib path
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '../../../../lib'))

from metasploit import module
from msf.http_client import HTTPClient, CheckCode

metadata = {
    'name': 'Acronis Cyber Protect/Backup machine info disclosure',
    'description': '''
        Acronis Cyber Protect or Backup is an enterprise backup/recovery solution for all,
        compute, storage and application resources. Businesses and Service Providers are using it
        to protect and backup all IT assets in their IT environment.
        This module exploits an authentication bypass vulnerability at the Acronis Cyber Protect
        appliance which, in its default configuration, allows the anonymous registration of new
        backup/protection agents on new endpoints. This API endpoint also generates bearer tokens
        which the agent then uses to authenticate to the appliance.
        As the management web console is running on the same port as the API for the agents, this
        bearer token is also valid for any actions on the web console. This allows an attacker
        with network access to the appliance to start the registration of a new agent, retrieve
        a bearer token that provides admin access to the available functions in the web console.
        
        This module will gather all machine info (endpoints) configured and managed by the appliance.
        This information can be used in a subsequent attack that exploits this vulnerability to
        execute arbitrary commands on both the managed endpoint and the appliance.
        This exploit is covered in another module `exploit/multi/acronis_cyber_protect_unauth_rce_cve_2022_3405`.
        
        Acronis Cyber Protect 15 (Windows, Linux) before build 29486 and
        Acronis Cyber Backup 12.5 (Windows, Linux) before build 16545 are vulnerable.
    ''',
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
