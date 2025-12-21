#!/usr/bin/env python3
# -*- coding: utf-8 -*-

##
# This module requires Metasploit: https://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

"""
Rex::Text equivalent in Python
Provides text manipulation utilities for Metasploit
"""

import struct
import base64


class Text:
    """Text manipulation utilities"""

    @staticmethod
    def pattern_create(length, sets=None):
        """
        Create a cyclic pattern of a given length
        
        Args:
            length: Length of pattern to create
            sets: Custom pattern character sets (list of strings)
                  Default is ['ABCDEFGHIJKLMNOPQRSTUVWXYZ', 'abcdefghijklmnopqrstuvwxyz', '0123456789']
        
        Returns:
            String containing the cyclic pattern
        """
        if sets is None:
            sets = [
                'ABCDEFGHIJKLMNOPQRSTUVWXYZ',
                'abcdefghijklmnopqrstuvwxyz',
                '0123456789'
            ]
        
        pattern = ''
        while len(pattern) < length:
            for char1 in sets[0]:
                for char2 in sets[1] if len(sets) > 1 else sets[0]:
                    for char3 in sets[2] if len(sets) > 2 else (sets[1] if len(sets) > 1 else sets[0]):
                        pattern += char1 + char2 + char3
                        if len(pattern) >= length:
                            return pattern[:length]
        
        return pattern[:length]

    @staticmethod
    def pattern_offset(pattern, query, start_offset=0):
        """
        Find the offset of a substring or integer in a pattern
        
        Args:
            pattern: The pattern to search in
            query: String or integer to find
            start_offset: Starting offset for the search
        
        Returns:
            Integer offset if found, None otherwise
        """
        if isinstance(query, int):
            # Convert integer to little-endian 4-byte string
            try:
                query_str = struct.pack('<I', query).decode('latin-1')
            except (struct.error, OverflowError):
                return None
        else:
            query_str = query
        
        try:
            offset = pattern.index(query_str, start_offset)
            return offset
        except ValueError:
            return None

    @staticmethod
    def decode_base64(data):
        """
        Decode base64 data
        
        Args:
            data: Base64 encoded string
        
        Returns:
            Decoded bytes
        """
        return base64.b64decode(data)

    @staticmethod
    def to_ascii(data):
        """
        Convert data to ASCII string
        
        Args:
            data: Bytes or string to convert
        
        Returns:
            ASCII string
        """
        if isinstance(data, bytes):
            # Remove null bytes and decode
            return data.rstrip(b'\x00').decode('ascii', errors='ignore')
        return str(data)


if __name__ == '__main__':
    # Simple test
    pattern = Text.pattern_create(100)
    print(f"Pattern (100 chars): {pattern}")
    
    # Test finding offset
    offset = Text.pattern_offset(pattern, "Aa3A")
    print(f"Offset of 'Aa3A': {offset}")
