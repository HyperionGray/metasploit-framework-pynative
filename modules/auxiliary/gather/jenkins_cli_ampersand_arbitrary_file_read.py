#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
Jenkins cli Ampersand Replacement Arbitrary File Read

This module utilizes the Jenkins cli protocol to run the `help` command.
The cli is accessible with read-only permissions by default, which are
all thats required.

Jenkins cli utilizes `args4j's` `parseArgument`, which calls `expandAtFiles` to
replace any `@<filename>` with the contents of a file. We are then able to retrieve
the error message to read up to the first two lines of a file.

Exploitation by hand can be done with the cli, see markdown documents for additional
instructions.

There are a few exploitation oddities:
1. The injection point for the `help` command requires 2 input arguments.
When the `expandAtFiles` is called, each line of the `FILE_PATH` becomes an input argument.
If a file only contains one line, it will throw an error: `ERROR: You must authenticate to access this Jenkins.`
However, we can pad out the content by supplying a first argument.
2. There is a strange timing requirement where the `download` (or first) request must get
to the server first, but the `upload` (or second) request must be very close behind it.
From testing against the docker image, it was found values between `.01` and `1.9` were
viable. Due to the round trip time of the first request and response happening before
request 2 would be received, it is necessary to use threading to ensure the requests
happen within rapid succession.

Files of value:
* /var/jenkins_home/secret.key
* /var/jenkins_home/secrets/master.key
* /var/jenkins_home/secrets/initialAdminPassword
* /etc/passwd
* /etc/shadow
* Project secrets and credentials
* Source code, build artifacts
"""

import logging
import sys
import os

# Add lib path
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '../../../../lib'))

from metasploit import module
from msf.http_client import HTTPClient, CheckCode

metadata = {
    'name': 'Jenkins cli Ampersand Replacement Arbitrary File Read',
    'description': '''
        This module utilizes the Jenkins cli protocol to run the `help` command.
        The cli is accessible with read-only permissions by default, which are
        all thats required.
        
        Jenkins cli utilizes `args4j's` `parseArgument`, which calls `expandAtFiles` to
        replace any `@<filename>` with the contents of a file. We are then able to retrieve
        the error message to read up to the first two lines of a file.
        
        Exploitation by hand can be done with the cli, see markdown documents for additional
        instructions.
        
        There are a few exploitation oddities:
        1. The injection point for the `help` command requires 2 input arguments.
        When the `expandAtFiles` is called, each line of the `FILE_PATH` becomes an input argument.
        If a file only contains one line, it will throw an error: `ERROR: You must authenticate to access this Jenkins.`
        However, we can pad out the content by supplying a first argument.
        2. There is a strange timing requirement where the `download` (or first) request must get
        to the server first, but the `upload` (or second) request must be very close behind it.
        From testing against the docker image, it was found values between `.01` and `1.9` were
        viable. Due to the round trip time of the first request and response happening before
        request 2 would be received, it is necessary to use threading to ensure the requests
        happen within rapid succession.
        
        Files of value:
        * /var/jenkins_home/secret.key
        * /var/jenkins_home/secrets/master.key
        * /var/jenkins_home/secrets/initialAdminPassword
        * /etc/passwd
        * /etc/shadow
        * Project secrets and credentials
        * Source code, build artifacts
    ''',
    'authors': [
        'h00die',
        'Yaniv Nizry',
        'binganao',
        'h4x0r-dz',
        'Vozec',
    ],
    'date': '2024-01-24',
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
