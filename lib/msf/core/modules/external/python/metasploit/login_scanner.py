"""
Login scanner helper for Metasploit external Python modules.

This module provides utilities for building password-spraying and
brute-force authentication scanners that integrate with Metasploit.
"""

import time

from metasploit import module


def make_scanner(login_callback):
    """
    Create a scanner function from a login callback.

    Args:
        login_callback: Function that takes (rhost, rport, username, password)
                        and returns True on successful authentication

    Returns:
        Scanner function that can be passed to module.run()

    Example:
        def try_login(host, port, user, password):
            # Attempt authentication
            return success

        scanner = make_scanner(try_login)
        module.run(metadata, scanner)
    """
    return lambda args: run_scanner(args, login_callback)


def run_scanner(args, login_callback):
    """
    Execute the login scanner with the provided credentials.

    Iterates through username/password combinations, calling the login
    callback for each attempt and reporting results to Metasploit.

    Args:
        args: Dictionary containing:
            - userpass: List of username/password pairs or newline-separated string
            - rhost: Target host
            - rport: Target port
            - sleep_interval: Optional delay between attempts
        login_callback: Function that takes (rhost, rport, username, password)
                        and returns True on successful authentication
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
