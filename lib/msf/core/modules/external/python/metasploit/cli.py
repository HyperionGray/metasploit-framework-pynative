"""
Command Line Interface utilities for Metasploit external Python modules.

This module provides CLI functionality for external Python modules when they
are run in standalone mode outside of the Metasploit framework.
"""

from __future__ import print_function

import argparse
import json
import re
import sys


def eprint(*args, **kwargs):
    """
    Print to stderr.
    
    Args:
        *args: Arguments to print
        **kwargs: Keyword arguments passed to print()
    """
    print(*args, file=sys.stderr, **kwargs)


def log(message, level='info'):
    """
    Log a message to stderr with appropriate formatting.
    
    Args:
        message (str): The message to log
        level (str, optional): Log level ('info', 'warning', 'error', 'good').
                              Defaults to 'info'.
    """
    # logging goes to stderr
    sigil = '*'
    if level == 'warning' or level == 'error':
        sigil = '!'
    elif level == 'good':
        sigil = '+'
    eprint('[{}] {}'.format(sigil, message))


def report(kind, data):
    """
    Print a report to stdout.
    
    Args:
        kind (str): Type of report ('host', 'service', 'vuln', etc.)
        data (dict): Report data
    """
    # actual results go to stdout
    print("[+] Found {}: {}".format(kind, json.dumps(data, separators=(',', ':'))))


def ret(result):
    """
    Print a result to stdout.
    
    Args:
        result: The result to print
    """
    print(result)


def parse(meta):
    """
    Parse command line arguments based on module metadata.
    
    Args:
        meta (dict): Module metadata containing description, options, and capabilities
        
    Returns:
        dict: Parsed arguments in JSON-RPC format with id, params, and method
    """
    parser = argparse.ArgumentParser(description=meta['description'])
    actions = ['run'] + meta['capabilities']
    parser.add_argument(
            'action',
            nargs='?',
            metavar="ACTION",
            help="The action to take ({})".format(actions),
            default='run',
            choices=actions)

    required_group = parser.add_argument_group('required arguments')
    for opt, props in meta['options'].items():
        group = parser
        desc = props['description']
        required = props['required'] and (props.get('default', None) is None)
        if props.get('default', None) is not None:
            desc = "{}, (default: {})".format(props['description'], props['default'])

        if required:
            group = required_group
        group.add_argument(
                '--' + opt.replace('_', '-'),
                help=desc,
                default=props.get('default', None),
                type=choose_type(props['type']),
                required=required,
                dest=opt)

    opts = parser.parse_args()
    args = vars(opts)
    action = args['action']
    del args['action']
    return {'id': '0', 'params': args, 'method': action}


def choose_type(t):
    """
    Choose the appropriate Python type for a Metasploit option type.
    
    Args:
        t (str): Metasploit option type string
        
    Returns:
        type: Python type function (int, float, str, or comma_list)
    """
    if t == 'int' or t == 'port':
        return int
    elif t == 'float':
        return float
    elif re.search('range$', t):
        return comma_list
    else: # XXX TODO add validation for addresses and other MSF option types
        return str


def comma_list(v):
    """
    Convert a comma-separated string to a list.
    
    Args:
        v (str): Comma-separated string
        
    Returns:
        list: List of string values
    """
    return v.split(',')
