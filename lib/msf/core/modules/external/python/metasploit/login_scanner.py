"""
Login scanner utilities for Metasploit external Python modules.

This module provides functionality for creating login scanners that can
systematically test username/password combinations against network services.
"""

import time

from metasploit import module


def make_scanner(login_callback):
    """
    Create a scanner function that uses the provided login callback.
    
    Args:
        login_callback (callable): Function that attempts login with signature
                                  (host, port, username, password) -> bool
                                  
    Returns:
        callable: Scanner function that can be used as a module callback
    """
    return lambda args: run_scanner(args, login_callback)


def run_scanner(args, login_callback):
    """
    Run a login scanner with the provided arguments and login callback.
    
    This function iterates through username/password combinations and calls
    the login callback for each attempt, reporting results back to the framework.
    
    Args:
        args (dict): Module arguments containing:
                    - userpass: List of username/password combinations
                    - rhost: Target host IP address
                    - rport: Target port number
                    - sleep_interval: Delay between login attempts
        login_callback (callable): Function that attempts login with signature
                                  (host, port, username, password) -> bool
    """
    userpass = args['userpass'] or []
    rhost = args['rhost']
    rport = int(args['rport'])
    sleep_interval = float(args['sleep_interval'] or 0)
    # python 2/3 compatibility hack
    if isinstance(userpass, str) or ('unicode' in dir(__builtins__) and isinstance(userpass, unicode)):
        userpass = [ attempt.split(' ', 1) for attempt in userpass.splitlines() ]

    curr = 0
    total = len(userpass)
    pad_to = len(str(total))

    for [username, password] in userpass:
        try:
            # Call per-combo login function
            curr += 1
            if login_callback(rhost, rport, username, password):
                module.log('{}:{} - [{:>{pad_to}}/{}] - {}:{} - Success'
                        .format(rhost, rport, curr, total, username, password, pad_to=pad_to), level='good')
                module.report_correct_password(username, password)
            else:
                module.log('{}:{} - [{:>{pad_to}}/{}] - {}:{} - Failure'
                        .format(rhost, rport, curr, total, username, password, pad_to=pad_to), level='info')
                module.report_wrong_password(username, password)

            time.sleep(sleep_interval)
        except Exception as e:
            module.log('{}:{} - [{:>{pad_to}}/{}] - {}:{} - Error: {}'
                    .format(rhost, rport, curr, total, username, password, e, pad_to=pad_to), level='error')
