#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Rex Text utilities
"""

import random
import string
import hashlib


class Text:
    """Text manipulation and generation utilities"""
    
    @staticmethod
    def rand_text_alpha(min_len: int = 8, max_len: int = None) -> str:
        """
        Generate random alphabetic text
        
        Args:
            min_len: Minimum length or exact length if max_len is None
            max_len: Maximum length (optional)
            
        Returns:
            Random alphabetic string
        """
        if max_len is None:
            length = min_len
        else:
            length = random.randint(min_len, max_len)
        return ''.join(random.choice(string.ascii_letters) for _ in range(length))
        
    @staticmethod
    def rand_text_alphanumeric(min_len: int = 8, max_len: int = None) -> str:
        """
        Generate random alphanumeric text
        
        Args:
            min_len: Minimum length or exact length if max_len is None
            max_len: Maximum length (optional)
            
        Returns:
            Random alphanumeric string
        """
        if max_len is None:
            length = min_len
        else:
            length = random.randint(min_len, max_len)
        return ''.join(random.choice(string.ascii_letters + string.digits) for _ in range(length))
        
    @staticmethod
    def rand_text_numeric(min_len: int = 8, max_len: int = None) -> str:
        """
        Generate random numeric text
        
        Args:
            min_len: Minimum length or exact length if max_len is None
            max_len: Maximum length (optional)
            
        Returns:
            Random numeric string
        """
        if max_len is None:
            length = min_len
        else:
            length = random.randint(min_len, max_len)
        return ''.join(random.choice(string.digits) for _ in range(length))
        
    @staticmethod
    def rand_text_hex(min_len: int = 8, max_len: int = None) -> str:
        """
        Generate random hexadecimal text
        
        Args:
            min_len: Minimum length or exact length if max_len is None
            max_len: Maximum length (optional)
            
        Returns:
            Random hex string
        """
        if max_len is None:
            length = min_len
        else:
            length = random.randint(min_len, max_len)
        return ''.join(random.choice(string.hexdigits.lower()) for _ in range(length))
        
    @staticmethod
    def md5(data: bytes) -> str:
        """
        Calculate MD5 hash
        
        Args:
            data: Data to hash
            
        Returns:
            Hex digest string
        """
        return hashlib.md5(data).hexdigest()
        
    @staticmethod
    def encode_base64(data: bytes) -> str:
        """
        Base64 encode data
        
        Args:
            data: Data to encode
            
        Returns:
            Base64 encoded string
        """
        import base64
        return base64.b64encode(data).decode('ascii')
        
    @staticmethod
    def decode_base64(data: str) -> bytes:
        """
        Base64 decode data
        
        Args:
            data: Base64 string to decode
            
        Returns:
            Decoded bytes
        """
        import base64
        return base64.b64decode(data)
        
    @staticmethod
    def uri_encode(data: str) -> str:
        """
        URL encode string
        
        Args:
            data: String to encode
            
        Returns:
            URL encoded string
        """
        from urllib.parse import quote
        return quote(data)
        
    @staticmethod
    def uri_decode(data: str) -> str:
        """
        URL decode string
        
        Args:
            data: String to decode
            
        Returns:
            URL decoded string
        """
        from urllib.parse import unquote
        return unquote(data)
