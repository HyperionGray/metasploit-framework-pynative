#!/usr/bin/env python3
# -*- coding: utf-8 -*-
##
# This module requires Metasploit: https://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

"""
Unix Command Shell, Bind TCP (stub)

This is a stub payload that generates an empty payload. It is used as a
placeholder when a handler is needed without an actual payload.
"""


class MetasploitModule:
    """
    Unix Command Shell, Bind TCP (stub)
    
    A stub payload that generates an empty payload string. This is used
    when you need a bind TCP handler but don't need to transmit an actual
    payload to the target.
    """
    
    # Payload metadata
    CachedSize = 0
    
    def __init__(self):
        self.module_info = {
            'Name': 'Unix Command Shell, Bind TCP (stub)',
            'Description': 'Listen for a connection and spawn a command shell (stub only, no payload)',
            'Author': ['hdm'],
            'License': 'MSF_LICENSE',
            'Platform': 'unix',
            'Arch': 'cmd',
            'Handler': 'bind_tcp',
            'Session': 'command_shell',
            'PayloadType': 'cmd_bind_stub',
            'RequiredCmd': '',
            'Payload': {
                'Offsets': {},
                'Payload': ''
            }
        }
    
    def generate(self, opts=None):
        """
        Generate an empty payload.
        
        Args:
            opts: Optional configuration options (unused)
            
        Returns:
            str: An empty string representing no payload
        """
        return ''
