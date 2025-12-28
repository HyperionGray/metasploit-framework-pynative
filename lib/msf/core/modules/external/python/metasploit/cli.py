"""
Command-line interface utilities for Metasploit external Python modules.

This module provides functions for parsing command-line arguments,
logging, and reporting when modules are run in CLI mode rather than
via the JSON-RPC interface.
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
        message: Message to log
        level: Log level ('info', 'warning', 'error', 'good', 'debug')
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
    Report discovered data to stdout.

    Args:
        kind: Type of data (host, service, vuln, etc.)
        data: Dictionary containing the data
    """
    # actual results go to stdout
    print("[+] Found {}: {}".format(kind, json.dumps(data, separators=(',', ':'))))


def ret(result):
    """
    Return a result value to stdout.

    Args:
        result: Result value to output
    """
    print(result)


def parse(meta):
    """
    Parse command-line arguments based on module metadata.

    Creates an argument parser from module metadata and parses command-line
    arguments into a JSON-RPC request format.

    Args:
        meta: Module metadata dictionary containing:
            - description: Module description
            - capabilities: List of supported actions
            - options: Dictionary of module options

    Returns:
        Dictionary in JSON-RPC request format with 'id', 'params', and 'method'

    Example:
        meta = {
            'description': 'Example module',
            'capabilities': ['soft_check'],
            'options': {
                'rhost': {'type': 'address', 'required': True, 'description': 'Target'},
            }
        }
        request = parse(meta)
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
    Convert Metasploit option type to Python type for argument parsing.

    Args:
        t: Metasploit option type string ('int', 'port', 'float',
           'address', 'address_range', etc.)

    Returns:
        Python type or conversion function for argparse
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
    Split a comma-separated string into a list.

    Args:
        v: Comma-separated string

    Returns:
        List of strings split on commas
    """
    return v.split(',')
