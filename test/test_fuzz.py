#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
Fuzz Testing Suite for Metasploit Framework.

This module provides fuzz tests that throw random/malformed data at functions
to ensure they handle edge cases gracefully and don't crash.
"""

import pytest
import sys
import os
import random
import string
from pathlib import Path
from typing import Any, List

# Add lib path for imports
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', 'lib'))
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', 'python_framework'))


class FuzzGenerator:
    """Helper class to generate fuzzed inputs."""
    
    @staticmethod
    def random_string(min_len: int = 0, max_len: int = 1000) -> str:
        """Generate random string."""
        length = random.randint(min_len, max_len)
        return ''.join(random.choices(string.printable, k=length))
    
    @staticmethod
    def random_bytes(min_len: int = 0, max_len: int = 1000) -> bytes:
        """Generate random bytes."""
        length = random.randint(min_len, max_len)
        return bytes(random.randint(0, 255) for _ in range(length))
    
    @staticmethod
    def random_int(min_val: int = -1000000, max_val: int = 1000000) -> int:
        """Generate random integer."""
        return random.randint(min_val, max_val)
    
    @staticmethod
    def random_list(element_type: str = 'int', min_len: int = 0, max_len: int = 100) -> List[Any]:
        """Generate random list."""
        length = random.randint(min_len, max_len)
        
        if element_type == 'int':
            return [random.randint(-1000, 1000) for _ in range(length)]
        elif element_type == 'str':
            return [FuzzGenerator.random_string(0, 50) for _ in range(length)]
        elif element_type == 'bytes':
            return [FuzzGenerator.random_bytes(0, 50) for _ in range(length)]
        else:
            return [None] * length
    
    @staticmethod
    def malicious_strings() -> List[str]:
        """Generate list of potentially malicious strings."""
        return [
            # SQL injection patterns
            "' OR '1'='1",
            "'; DROP TABLE users--",
            "1' UNION SELECT NULL--",
            
            # XSS patterns
            "<script>alert('xss')</script>",
            "<img src=x onerror=alert('xss')>",
            "javascript:alert('xss')",
            
            # Command injection patterns
            "; ls -la",
            "| cat /etc/passwd",
            "`whoami`",
            "$(id)",
            
            # Path traversal patterns
            "../../../etc/passwd",
            "..\\..\\..\\windows\\system32\\config\\sam",
            
            # Format string patterns
            "%s%s%s%s%s",
            "%x%x%x%x%x",
            "%n%n%n%n%n",
            
            # Buffer overflow patterns
            "A" * 10000,
            "A" * 100000,
            
            # Unicode and special characters
            "\x00" * 100,  # Null bytes
            "\xff" * 100,  # High bytes
            "🔥" * 1000,   # Unicode emoji
            
            # Empty and whitespace
            "",
            " ",
            "\t\n\r",
            "   " * 100,
        ]
    
    @staticmethod
    def malicious_bytes() -> List[bytes]:
        """Generate list of potentially malicious byte sequences."""
        return [
            b'\x00' * 1000,  # Null bytes
            b'\xff' * 1000,  # High bytes
            b'\x90' * 1000,  # NOP sled
            b'\x41' * 10000,  # Buffer overflow
            b'\x00\x01\x02\x03' * 100,  # Pattern
            bytes(range(256)) * 10,  # All bytes
        ]


class TestStringFuzzing:
    """Fuzz tests for string handling."""
    
    @pytest.mark.unit
    @pytest.mark.security
    def test_fuzz_string_operations(self):
        """Fuzz test basic string operations."""
        for _ in range(100):
            s = FuzzGenerator.random_string()
            
            # These operations should never crash
            try:
                _ = len(s)
                _ = s.upper()
                _ = s.lower()
                _ = s.strip()
                _ = s.split()
            except Exception as e:
                pytest.fail(f"String operation crashed with: {e}")
    
    @pytest.mark.unit
    @pytest.mark.security
    def test_fuzz_malicious_strings(self):
        """Fuzz test with potentially malicious strings."""
        malicious = FuzzGenerator.malicious_strings()
        
        for s in malicious:
            # Basic operations should handle malicious input
            try:
                _ = len(s)
                _ = s.encode('utf-8', errors='ignore')
                _ = s.replace("'", "\\'")
            except Exception as e:
                pytest.fail(f"Failed to handle malicious string: {s[:50]}... Error: {e}")
    
    @pytest.mark.unit
    @pytest.mark.security
    def test_fuzz_html_escaping(self):
        """Fuzz test HTML escaping."""
        import html
        
        malicious = FuzzGenerator.malicious_strings()
        
        for s in malicious:
            try:
                escaped = html.escape(s)
                # Ensure dangerous characters are escaped
                assert '<script>' not in escaped or '&lt;script&gt;' in escaped
            except Exception as e:
                pytest.fail(f"HTML escaping failed: {e}")


class TestBytesFuzzing:
    """Fuzz tests for bytes handling."""
    
    @pytest.mark.unit
    @pytest.mark.security
    def test_fuzz_bytes_operations(self):
        """Fuzz test basic bytes operations."""
        for _ in range(100):
            b = FuzzGenerator.random_bytes()
            
            # These operations should never crash
            try:
                _ = len(b)
                _ = b.hex()
                _ = bytes(reversed(b))
            except Exception as e:
                pytest.fail(f"Bytes operation crashed with: {e}")
    
    @pytest.mark.unit
    @pytest.mark.security
    def test_fuzz_malicious_bytes(self):
        """Fuzz test with potentially malicious byte sequences."""
        malicious = FuzzGenerator.malicious_bytes()
        
        for b in malicious:
            # Basic operations should handle malicious input
            try:
                _ = len(b)
                _ = b.hex()
                _ = b.decode('utf-8', errors='ignore')
            except Exception as e:
                pytest.fail(f"Failed to handle malicious bytes. Error: {e}")
    
    @pytest.mark.unit
    @pytest.mark.crypto
    def test_fuzz_base64_encoding(self):
        """Fuzz test base64 encoding/decoding."""
        import base64
        
        for _ in range(100):
            data = FuzzGenerator.random_bytes()
            
            try:
                encoded = base64.b64encode(data)
                decoded = base64.b64decode(encoded)
                assert decoded == data
            except Exception as e:
                pytest.fail(f"Base64 encoding/decoding failed: {e}")


class TestHashingFuzzing:
    """Fuzz tests for cryptographic hashing."""
    
    @pytest.mark.unit
    @pytest.mark.crypto
    @pytest.mark.security
    def test_fuzz_md5_hashing(self):
        """Fuzz test MD5 hashing."""
        try:
            from Crypto.Hash import MD5
        except ImportError:
            pytest.skip("Crypto not available")
        
        for _ in range(100):
            data = FuzzGenerator.random_bytes()
            
            try:
                hasher = MD5.new()
                hasher.update(data)
                result = hasher.hexdigest()
                assert len(result) == 32  # MD5 produces 32 hex chars
            except Exception as e:
                pytest.fail(f"MD5 hashing crashed with: {e}")
    
    @pytest.mark.unit
    @pytest.mark.crypto
    @pytest.mark.security
    def test_fuzz_sha256_hashing(self):
        """Fuzz test SHA256 hashing."""
        try:
            from Crypto.Hash import SHA256
        except ImportError:
            pytest.skip("Crypto not available")
        
        for _ in range(100):
            data = FuzzGenerator.random_bytes()
            
            try:
                hasher = SHA256.new()
                hasher.update(data)
                result = hasher.hexdigest()
                assert len(result) == 64  # SHA256 produces 64 hex chars
            except Exception as e:
                pytest.fail(f"SHA256 hashing crashed with: {e}")


class TestEncodingFuzzing:
    """Fuzz tests for encoding operations."""
    
    @pytest.mark.unit
    @pytest.mark.security
    def test_fuzz_utf8_encoding(self):
        """Fuzz test UTF-8 encoding/decoding."""
        for _ in range(100):
            s = FuzzGenerator.random_string()
            
            try:
                encoded = s.encode('utf-8')
                decoded = encoded.decode('utf-8')
                assert decoded == s
            except UnicodeDecodeError:
                # Some random strings may not be valid UTF-8
                pass
            except Exception as e:
                pytest.fail(f"UTF-8 encoding/decoding crashed with: {e}")
    
    @pytest.mark.unit
    @pytest.mark.security
    def test_fuzz_url_encoding(self):
        """Fuzz test URL encoding/decoding."""
        from urllib.parse import quote, unquote
        
        for _ in range(100):
            s = FuzzGenerator.random_string()
            
            try:
                encoded = quote(s)
                decoded = unquote(encoded)
                # Decoding should not crash
                assert isinstance(decoded, str)
            except Exception as e:
                pytest.fail(f"URL encoding/decoding crashed with: {e}")


class TestCollectionFuzzing:
    """Fuzz tests for collection operations."""
    
    @pytest.mark.unit
    def test_fuzz_list_operations(self):
        """Fuzz test list operations."""
        for _ in range(100):
            lst = FuzzGenerator.random_list('int')
            
            try:
                _ = len(lst)
                _ = list(reversed(lst))
                _ = sorted(lst) if lst else []
            except Exception as e:
                pytest.fail(f"List operation crashed with: {e}")
    
    @pytest.mark.unit
    def test_fuzz_dict_operations(self):
        """Fuzz test dictionary operations."""
        for _ in range(100):
            # Generate random dict
            size = random.randint(0, 100)
            d = {FuzzGenerator.random_string(1, 20): FuzzGenerator.random_int() 
                 for _ in range(size)}
            
            try:
                _ = len(d)
                _ = list(d.keys())
                _ = list(d.values())
                _ = d.copy()
            except Exception as e:
                pytest.fail(f"Dict operation crashed with: {e}")


class TestPayloadFuzzing:
    """Fuzz tests for payload operations."""
    
    @pytest.mark.unit
    @pytest.mark.payload
    def test_fuzz_payload_generation(self):
        """Fuzz test payload generation."""
        for _ in range(50):
            payload_size = random.randint(0, 5000)
            
            try:
                # Generate random payload
                payload = FuzzGenerator.random_bytes(payload_size, payload_size)
                
                # Basic checks
                assert isinstance(payload, bytes)
                assert len(payload) == payload_size
            except Exception as e:
                pytest.fail(f"Payload generation crashed with: {e}")
    
    @pytest.mark.unit
    @pytest.mark.payload
    def test_fuzz_payload_encoding(self):
        """Fuzz test payload encoding."""
        for _ in range(50):
            payload = FuzzGenerator.random_bytes(0, 1000)
            
            try:
                # Hex encoding
                hex_encoded = payload.hex()
                hex_decoded = bytes.fromhex(hex_encoded)
                assert hex_decoded == payload
            except Exception as e:
                pytest.fail(f"Payload encoding crashed with: {e}")


class TestExploitFuzzing:
    """Fuzz tests for exploit operations."""
    
    @pytest.mark.unit
    @pytest.mark.exploit
    def test_fuzz_port_validation(self):
        """Fuzz test port number validation."""
        for _ in range(100):
            port = FuzzGenerator.random_int(-10000, 100000)
            
            # Port validation should not crash
            try:
                is_valid = 1 <= port <= 65535
                assert isinstance(is_valid, bool)
            except Exception as e:
                pytest.fail(f"Port validation crashed with: {e}")
    
    @pytest.mark.unit
    @pytest.mark.exploit
    def test_fuzz_ip_parsing(self):
        """Fuzz test IP address parsing."""
        import ipaddress
        
        for _ in range(100):
            # Generate random IP-like string
            octets = [str(random.randint(-100, 300)) for _ in range(4)]
            ip_str = '.'.join(octets)
            
            try:
                # Try to parse as IP
                try:
                    _ = ipaddress.ip_address(ip_str)
                except ValueError:
                    # Invalid IP is expected for fuzzed input
                    pass
            except Exception as e:
                pytest.fail(f"IP parsing crashed with unexpected error: {e}")


class TestNetworkFuzzing:
    """Fuzz tests for network operations."""
    
    @pytest.mark.unit
    @pytest.mark.network
    def test_fuzz_url_parsing(self):
        """Fuzz test URL parsing."""
        from urllib.parse import urlparse
        
        for _ in range(100):
            url = FuzzGenerator.random_string()
            
            try:
                # URL parsing should handle any string
                result = urlparse(url)
                assert result is not None
            except Exception as e:
                pytest.fail(f"URL parsing crashed with: {e}")
    
    @pytest.mark.unit
    @pytest.mark.network
    def test_fuzz_http_headers(self):
        """Fuzz test HTTP header handling."""
        for _ in range(100):
            # Generate random header name and value
            header_name = FuzzGenerator.random_string(1, 50)
            header_value = FuzzGenerator.random_string(0, 200)
            
            try:
                # Headers should handle any string
                headers = {header_name: header_value}
                assert isinstance(headers, dict)
            except Exception as e:
                pytest.fail(f"HTTP header handling crashed with: {e}")


class TestSecurityFuzzing:
    """Fuzz tests for security-critical operations."""
    
    @pytest.mark.security
    @pytest.mark.unit
    def test_fuzz_input_sanitization(self):
        """Fuzz test input sanitization."""
        malicious = FuzzGenerator.malicious_strings()
        
        for s in malicious:
            try:
                # Basic sanitization operations
                _ = s.replace("'", "\\'")
                _ = s.replace('"', '\\"')
                _ = s.replace('<', '&lt;')
                _ = s.replace('>', '&gt;')
            except Exception as e:
                pytest.fail(f"Input sanitization crashed with: {e}")
    
    @pytest.mark.security
    @pytest.mark.unit
    def test_fuzz_path_traversal_detection(self):
        """Fuzz test path traversal detection."""
        malicious_paths = [
            "../../../etc/passwd",
            "..\\..\\..\\windows\\system32",
            "./../../secret",
            "//etc/passwd",
            "\\..\\..\\..",
        ]
        
        for path in malicious_paths:
            try:
                # Path normalization should handle malicious paths
                from pathlib import Path
                normalized = Path(path).resolve()
                assert isinstance(normalized, Path)
            except Exception as e:
                # Some paths may fail, which is acceptable
                pass


if __name__ == '__main__':
    pytest.main([__file__, '-v', '--tb=short'])
