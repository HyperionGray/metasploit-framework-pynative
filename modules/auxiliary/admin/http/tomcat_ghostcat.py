#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
Apache Tomcat AJP File Read

When using the Apache JServ Protocol (AJP), care must be taken when trusting incoming connections to Apache
Tomcat. Tomcat treats AJP connections as having higher trust than, for example, a similar HTTP connection.
If such connections are available to an attacker, they can be exploited in ways that may be surprising.

In Apache Tomcat 9.0.0.M1 to 9.0.0.30, 8.5.0 to 8.5.50 and 7.0.0 to 7.0.99, Tomcat shipped with an AJP
Connector enabled by default that listened on all configured IP addresses. It was expected (and recommended
in the security guide) that this Connector would be disabled if not required. This vulnerability report
identified a mechanism that allowed: - returning arbitrary files from anywhere in the web application -
processing any file in the web application as a JSP. Further, if the web application allowed file upload
and stored those files within the web application (or the attacker was able to control the content of the
web application by some other means) then this, along with the ability to process a file as a JSP, made
remote code execution possible.

It is important to note that mitigation is only required if an AJP port is accessible to untrusted users.
Users wishing to take a defence-in-depth approach and block the vector that permits returning arbitrary files
and execution as JSP may upgrade to Apache Tomcat 9.0.31, 8.5.51 or 7.0.100 or later. A number of changes were
made to the default AJP Connector configuration in 9.0.31 to harden the default configuration.
It is likely that users upgrading to 9.0.31, 8.5.51 or 7.0.100 or later will need to make small changes
to their configurations.
"""

import logging
import sys
import os

# Add lib path
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '../../../../lib'))

from metasploit import module
from msf.http_client import HTTPClient, CheckCode

metadata = {
    'name': 'Apache Tomcat AJP File Read',
    'description': '''
        When using the Apache JServ Protocol (AJP), care must be taken when trusting incoming connections to Apache
        Tomcat. Tomcat treats AJP connections as having higher trust than, for example, a similar HTTP connection.
        If such connections are available to an attacker, they can be exploited in ways that may be surprising.
        
        In Apache Tomcat 9.0.0.M1 to 9.0.0.30, 8.5.0 to 8.5.50 and 7.0.0 to 7.0.99, Tomcat shipped with an AJP
        Connector enabled by default that listened on all configured IP addresses. It was expected (and recommended
        in the security guide) that this Connector would be disabled if not required. This vulnerability report
        identified a mechanism that allowed: - returning arbitrary files from anywhere in the web application -
        processing any file in the web application as a JSP. Further, if the web application allowed file upload
        and stored those files within the web application (or the attacker was able to control the content of the
        web application by some other means) then this, along with the ability to process a file as a JSP, made
        remote code execution possible.
        
        It is important to note that mitigation is only required if an AJP port is accessible to untrusted users.
        Users wishing to take a defence-in-depth approach and block the vector that permits returning arbitrary files
        and execution as JSP may upgrade to Apache Tomcat 9.0.31, 8.5.51 or 7.0.100 or later. A number of changes were
        made to the default AJP Connector configuration in 9.0.31 to harden the default configuration.
        It is likely that users upgrading to 9.0.31, 8.5.51 or 7.0.100 or later will need to make small changes
        to their configurations.
    ''',
    'authors': [
        'A Security Researcher of Chaitin Tech',
        'SunCSR Team',
    ],
    'date': '2020-02-20',
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
