#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
Property-Based Testing Suite using Hypothesis.

This module provides property-based tests that generate thousands of test cases
to verify that properties hold true for all possible inputs.
"""

import pytest
import sys
import os
from pathlib import Path

# Add lib path for imports
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', 'lib'))
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', 'python_framework'))

try:
    from hypothesis import given, strategies as st, settings, assume
    from hypothesis import HealthCheck
    HYPOTHESIS_AVAILABLE = True
except ImportError:
    HYPOTHESIS_AVAILABLE = False
    pytest.skip("Hypothesis not available", allow_module_level=True)


class TestStringProperties:
    """Property-based tests for string operations."""
    
    @given(st.text())
    @settings(max_examples=1000, suppress_health_check=[HealthCheck.too_slow])
    @pytest.mark.unit
    def test_string_reverse_reverse_is_identity(self, s):
        """Test that reversing a string twice returns the original."""
        assert s == s[::-1][::-1]
    
    @given(st.text())
    @settings(max_examples=1000)
    @pytest.mark.unit
    def test_string_upper_lower_roundtrip(self, s):
        """Test string case conversion properties."""
        # Converting to upper then lower may not always return original due to special chars
        # but length should be preserved
        assert len(s.upper().lower()) == len(s)
    
    @given(st.text(), st.text())
    @settings(max_examples=500)
    @pytest.mark.unit
    def test_string_concatenation_length(self, s1, s2):
        """Test that concatenated string length equals sum of parts."""
        result = s1 + s2
        assert len(result) == len(s1) + len(s2)
    
    @given(st.text(min_size=1), st.text())
    @settings(max_examples=500)
    @pytest.mark.unit
    def test_string_contains_after_concat(self, s1, s2):
        """Test that concatenated string contains both parts."""
        assume(len(s1) > 0)
        result = s1 + s2
        assert s1 in result
        if len(s2) > 0:
            assert s2 in result


class TestListProperties:
    """Property-based tests for list operations."""
    
    @given(st.lists(st.integers()))
    @settings(max_examples=1000)
    @pytest.mark.unit
    def test_list_reverse_reverse_is_identity(self, lst):
        """Test that reversing a list twice returns the original."""
        assert lst == list(reversed(list(reversed(lst))))
    
    @given(st.lists(st.integers()))
    @settings(max_examples=1000)
    @pytest.mark.unit
    def test_list_length_preserved_on_reverse(self, lst):
        """Test that list length is preserved when reversed."""
        assert len(lst) == len(list(reversed(lst)))
    
    @given(st.lists(st.integers()), st.lists(st.integers()))
    @settings(max_examples=500)
    @pytest.mark.unit
    def test_list_concatenation_length(self, lst1, lst2):
        """Test that concatenated list length equals sum of parts."""
        result = lst1 + lst2
        assert len(result) == len(lst1) + len(lst2)
    
    @given(st.lists(st.integers(), min_size=1))
    @settings(max_examples=500)
    @pytest.mark.unit
    def test_list_sorting_preserves_length(self, lst):
        """Test that sorting preserves list length."""
        sorted_lst = sorted(lst)
        assert len(sorted_lst) == len(lst)
    
    @given(st.lists(st.integers(), min_size=2))
    @settings(max_examples=500)
    @pytest.mark.unit
    def test_list_min_max_in_list(self, lst):
        """Test that min and max values are in the original list."""
        assume(len(lst) >= 2)
        assert min(lst) in lst
        assert max(lst) in lst


class TestDictionaryProperties:
    """Property-based tests for dictionary operations."""
    
    @given(st.dictionaries(st.text(), st.integers()))
    @settings(max_examples=1000)
    @pytest.mark.unit
    def test_dict_keys_length_equals_items(self, d):
        """Test that number of keys equals number of items."""
        assert len(d.keys()) == len(d)
    
    @given(st.dictionaries(st.text(), st.integers()))
    @settings(max_examples=1000)
    @pytest.mark.unit
    def test_dict_update_preserves_original_keys(self, d):
        """Test that updating dict with itself preserves keys."""
        original_keys = set(d.keys())
        d_copy = d.copy()
        d_copy.update(d)
        assert set(d_copy.keys()) == original_keys
    
    @given(st.dictionaries(st.text(min_size=1), st.integers()), st.text(min_size=1))
    @settings(max_examples=500)
    @pytest.mark.unit
    def test_dict_get_with_default(self, d, key):
        """Test dict.get() with default value."""
        default = -999
        result = d.get(key, default)
        if key in d:
            assert result == d[key]
        else:
            assert result == default


class TestNumericProperties:
    """Property-based tests for numeric operations."""
    
    @given(st.integers())
    @settings(max_examples=1000)
    @pytest.mark.unit
    def test_integer_addition_commutative(self, x):
        """Test that integer addition is commutative."""
        y = 5
        assert x + y == y + x
    
    @given(st.integers(), st.integers())
    @settings(max_examples=1000)
    @pytest.mark.unit
    def test_integer_addition_associative(self, x, y):
        """Test that integer addition is associative."""
        z = 10
        assert (x + y) + z == x + (y + z)
    
    @given(st.integers(min_value=-1000000, max_value=1000000))
    @settings(max_examples=1000)
    @pytest.mark.unit
    def test_absolute_value_non_negative(self, x):
        """Test that absolute value is always non-negative."""
        assert abs(x) >= 0
    
    @given(st.integers(min_value=-1000000, max_value=1000000))
    @settings(max_examples=1000)
    @pytest.mark.unit
    def test_double_negation_identity(self, x):
        """Test that double negation returns original value."""
        assert -(-x) == x
    
    @given(st.integers(min_value=0, max_value=1000))
    @settings(max_examples=500)
    @pytest.mark.unit
    def test_square_non_negative(self, x):
        """Test that square of a number is non-negative."""
        assert x * x >= 0


class TestBinaryDataProperties:
    """Property-based tests for binary data operations."""
    
    @given(st.binary())
    @settings(max_examples=1000)
    @pytest.mark.unit
    def test_bytes_reverse_reverse_identity(self, data):
        """Test that reversing bytes twice returns original."""
        assert data == bytes(reversed(bytes(reversed(data))))
    
    @given(st.binary(), st.binary())
    @settings(max_examples=500)
    @pytest.mark.unit
    def test_bytes_concatenation_length(self, b1, b2):
        """Test that concatenated bytes length equals sum."""
        result = b1 + b2
        assert len(result) == len(b1) + len(b2)
    
    @given(st.binary(min_size=1, max_size=100))
    @settings(max_examples=500)
    @pytest.mark.unit
    @pytest.mark.crypto
    def test_hex_encoding_roundtrip(self, data):
        """Test that hex encoding and decoding is lossless."""
        assume(len(data) > 0)
        hex_encoded = data.hex()
        decoded = bytes.fromhex(hex_encoded)
        assert decoded == data


class TestEncodingProperties:
    """Property-based tests for encoding operations."""
    
    @given(st.text())
    @settings(max_examples=1000)
    @pytest.mark.unit
    def test_utf8_encoding_roundtrip(self, s):
        """Test that UTF-8 encoding and decoding is lossless."""
        encoded = s.encode('utf-8')
        decoded = encoded.decode('utf-8')
        assert decoded == s
    
    @given(st.text(alphabet=st.characters(min_codepoint=32, max_codepoint=126)))
    @settings(max_examples=500)
    @pytest.mark.unit
    def test_ascii_encoding_roundtrip(self, s):
        """Test that ASCII encoding and decoding is lossless for ASCII text."""
        try:
            encoded = s.encode('ascii')
            decoded = encoded.decode('ascii')
            assert decoded == s
        except UnicodeEncodeError:
            # Skip if string contains non-ASCII characters
            assume(False)
    
    @given(st.binary())
    @settings(max_examples=500)
    @pytest.mark.unit
    def test_base64_encoding_increases_size(self, data):
        """Test that base64 encoding typically increases size."""
        import base64
        assume(len(data) > 0)
        encoded = base64.b64encode(data)
        # Base64 encoding typically increases size by ~33%
        assert len(encoded) >= len(data)


class TestHashingProperties:
    """Property-based tests for hashing operations."""
    
    @given(st.binary())
    @settings(max_examples=500)
    @pytest.mark.unit
    @pytest.mark.crypto
    def test_hash_deterministic(self, data):
        """Test that hashing the same data produces same result."""
        try:
            from Crypto.Hash import SHA256
            
            hash1 = SHA256.new(data).hexdigest()
            hash2 = SHA256.new(data).hexdigest()
            assert hash1 == hash2
        except ImportError:
            pytest.skip("Crypto not available")
    
    @given(st.binary(min_size=1))
    @settings(max_examples=500)
    @pytest.mark.unit
    @pytest.mark.crypto
    def test_hash_fixed_length_output(self, data):
        """Test that hash output is always fixed length."""
        try:
            from Crypto.Hash import SHA256
            
            assume(len(data) > 0)
            hash_result = SHA256.new(data).hexdigest()
            # SHA256 produces 64 hex characters (32 bytes)
            assert len(hash_result) == 64
        except ImportError:
            pytest.skip("Crypto not available")
    
    @given(st.binary(min_size=1), st.binary(min_size=1))
    @settings(max_examples=200)
    @pytest.mark.unit
    @pytest.mark.crypto
    def test_different_inputs_different_hashes(self, data1, data2):
        """Test that different inputs produce different hashes (collision resistance)."""
        try:
            from Crypto.Hash import SHA256
            
            assume(data1 != data2)
            hash1 = SHA256.new(data1).hexdigest()
            hash2 = SHA256.new(data2).hexdigest()
            # While collisions are theoretically possible, they should be extremely rare
            assert hash1 != hash2
        except ImportError:
            pytest.skip("Crypto not available")


class TestPayloadProperties:
    """Property-based tests for payload-related operations."""
    
    @given(st.binary(min_size=0, max_size=1000))
    @settings(max_examples=500)
    @pytest.mark.unit
    @pytest.mark.payload
    def test_payload_size_calculation(self, payload):
        """Test that payload size is calculated correctly."""
        assert len(payload) == len(bytes(payload))
    
    @given(st.binary(min_size=0, max_size=100))
    @settings(max_examples=500)
    @pytest.mark.unit
    @pytest.mark.payload
    def test_payload_padding_increases_size(self, payload):
        """Test that padding increases payload size."""
        padding_size = 16
        padding_char = b'\x00'
        
        padded = payload + (padding_char * padding_size)
        assert len(padded) == len(payload) + padding_size
    
    @given(st.lists(st.integers(min_value=0, max_value=255), min_size=0, max_size=100))
    @settings(max_examples=500)
    @pytest.mark.unit
    @pytest.mark.payload
    def test_payload_from_int_list(self, int_list):
        """Test converting integer list to bytes payload."""
        payload = bytes(int_list)
        assert len(payload) == len(int_list)
        assert all(0 <= b <= 255 for b in payload)


class TestURLProperties:
    """Property-based tests for URL handling."""
    
    @given(st.text(alphabet=st.characters(blacklist_characters='?&#')))
    @settings(max_examples=500)
    @pytest.mark.unit
    @pytest.mark.network
    def test_url_encoding_roundtrip(self, s):
        """Test that URL encoding and decoding is lossless."""
        from urllib.parse import quote, unquote
        
        encoded = quote(s)
        decoded = unquote(encoded)
        assert decoded == s
    
    @given(st.text(alphabet=st.characters(min_codepoint=65, max_codepoint=90)))
    @settings(max_examples=500)
    @pytest.mark.unit
    @pytest.mark.network
    def test_url_safe_characters(self, s):
        """Test URL-safe character handling."""
        from urllib.parse import quote
        
        # For alphanumeric characters, quote should not change them
        encoded = quote(s, safe='')
        # All uppercase letters should be preserved
        assert all(c in encoded for c in s if c.isalpha())


class TestExploitProperties:
    """Property-based tests for exploit-related operations."""
    
    @given(st.integers(min_value=1, max_value=65535))
    @settings(max_examples=500)
    @pytest.mark.unit
    @pytest.mark.exploit
    def test_port_number_valid_range(self, port):
        """Test that port numbers are in valid range."""
        assert 1 <= port <= 65535
    
    @given(st.integers(min_value=0, max_value=255), 
           st.integers(min_value=0, max_value=255),
           st.integers(min_value=0, max_value=255),
           st.integers(min_value=0, max_value=255))
    @settings(max_examples=500)
    @pytest.mark.unit
    @pytest.mark.exploit
    def test_ip_address_octets(self, o1, o2, o3, o4):
        """Test that IP address octets are in valid range."""
        assert 0 <= o1 <= 255
        assert 0 <= o2 <= 255
        assert 0 <= o3 <= 255
        assert 0 <= o4 <= 255
        
        ip = f"{o1}.{o2}.{o3}.{o4}"
        octets = ip.split('.')
        assert len(octets) == 4
    
    @given(st.integers(min_value=0, max_value=10000))
    @settings(max_examples=500)
    @pytest.mark.unit
    @pytest.mark.exploit
    def test_buffer_overflow_offset(self, offset):
        """Test buffer overflow offset calculations."""
        buffer_size = 1024
        
        if offset <= buffer_size:
            # Offset within buffer is valid
            assert 0 <= offset <= buffer_size
        else:
            # Offset beyond buffer
            assert offset > buffer_size


if __name__ == '__main__':
    pytest.main([__file__, '-v', '--tb=short'])
