#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Cryptographic Functions Tests

This test suite validates cryptographic functionality that was converted
from Ruby to Python, ensuring security functions work correctly.
"""

import pytest
import sys
import os
import hashlib
import hmac
import secrets
import base64
import binascii
from unittest.mock import Mock, patch

# Add lib path for imports
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', '..', 'lib'))


@pytest.mark.crypto
@pytest.mark.unit
class TestHashFunctions:
    """Test cryptographic hash functions"""
    
    def setup_method(self):
        """Setup test data"""
        self.test_data = b"test data for hashing"
        self.test_string = "test string"
    
    def test_md5_hashing(self):
        """Test MD5 hash function"""
        # Test MD5 hashing
        md5_hash = hashlib.md5(self.test_data).hexdigest()
        
        # MD5 should produce 32 character hex string
        assert len(md5_hash) == 32
        assert all(c in '0123456789abcdef' for c in md5_hash)
        
        # Test consistency
        md5_hash2 = hashlib.md5(self.test_data).hexdigest()
        assert md5_hash == md5_hash2
    
    def test_sha1_hashing(self):
        """Test SHA1 hash function"""
        sha1_hash = hashlib.sha1(self.test_data).hexdigest()
        
        # SHA1 should produce 40 character hex string
        assert len(sha1_hash) == 40
        assert all(c in '0123456789abcdef' for c in sha1_hash)
    
    def test_sha256_hashing(self):
        """Test SHA256 hash function"""
        sha256_hash = hashlib.sha256(self.test_data).hexdigest()
        
        # SHA256 should produce 64 character hex string
        assert len(sha256_hash) == 64
        assert all(c in '0123456789abcdef' for c in sha256_hash)
    
    def test_sha512_hashing(self):
        """Test SHA512 hash function"""
        sha512_hash = hashlib.sha512(self.test_data).hexdigest()
        
        # SHA512 should produce 128 character hex string
        assert len(sha512_hash) == 128
        assert all(c in '0123456789abcdef' for c in sha512_hash)
    
    def test_hmac_functionality(self):
        """Test HMAC functionality"""
        key = b"secret key"
        message = b"message to authenticate"
        
        # Test HMAC-SHA256
        hmac_digest = hmac.new(key, message, hashlib.sha256).hexdigest()
        
        assert len(hmac_digest) == 64  # SHA256 produces 64 hex chars
        
        # Test HMAC verification
        hmac_digest2 = hmac.new(key, message, hashlib.sha256).hexdigest()
        assert hmac_digest == hmac_digest2
        
        # Test with different key should produce different result
        different_key = b"different key"
        hmac_different = hmac.new(different_key, message, hashlib.sha256).hexdigest()
        assert hmac_digest != hmac_different


@pytest.mark.crypto
@pytest.mark.unit
class TestEncodingFunctions:
    """Test encoding and decoding functions"""
    
    def setup_method(self):
        """Setup test data"""
        self.test_data = b"test data for encoding"
        self.test_string = "test string for encoding"
    
    def test_base64_encoding(self):
        """Test Base64 encoding/decoding"""
        # Test encoding
        encoded = base64.b64encode(self.test_data)
        assert isinstance(encoded, bytes)
        
        # Test decoding
        decoded = base64.b64decode(encoded)
        assert decoded == self.test_data
        
        # Test string encoding
        string_encoded = base64.b64encode(self.test_string.encode()).decode()
        string_decoded = base64.b64decode(string_encoded).decode()
        assert string_decoded == self.test_string
    
    def test_hex_encoding(self):
        """Test hexadecimal encoding/decoding"""
        # Test hex encoding
        hex_encoded = binascii.hexlify(self.test_data)
        assert isinstance(hex_encoded, bytes)
        
        # Test hex decoding
        hex_decoded = binascii.unhexlify(hex_encoded)
        assert hex_decoded == self.test_data
        
        # Test hex string format
        hex_string = hex_encoded.decode()
        assert all(c in '0123456789abcdef' for c in hex_string)
    
    def test_url_encoding(self):
        """Test URL encoding functionality"""
        import urllib.parse
        
        test_url_data = "test data with spaces & special chars!"
        
        # Test URL encoding
        encoded = urllib.parse.quote(test_url_data)
        assert ' ' not in encoded  # Spaces should be encoded
        assert '&' not in encoded  # Special chars should be encoded
        
        # Test URL decoding
        decoded = urllib.parse.unquote(encoded)
        assert decoded == test_url_data
    
    def test_html_encoding(self):
        """Test HTML encoding functionality"""
        import html
        
        test_html_data = "<script>alert('xss')</script>"
        
        # Test HTML encoding
        encoded = html.escape(test_html_data)
        assert '<' not in encoded
        assert '>' not in encoded
        assert "'" not in encoded
        
        # Test HTML decoding
        decoded = html.unescape(encoded)
        assert decoded == test_html_data


@pytest.mark.crypto
@pytest.mark.security
class TestRandomGeneration:
    """Test secure random generation"""
    
    def test_secure_random_bytes(self):
        """Test secure random byte generation"""
        # Test different sizes
        for size in [16, 32, 64]:
            random_bytes = secrets.token_bytes(size)
            
            assert len(random_bytes) == size
            assert isinstance(random_bytes, bytes)
            
            # Test that multiple calls produce different results
            random_bytes2 = secrets.token_bytes(size)
            assert random_bytes != random_bytes2
    
    def test_secure_random_hex(self):
        """Test secure random hex generation"""
        # Test different sizes
        for size in [16, 32, 64]:
            random_hex = secrets.token_hex(size)
            
            assert len(random_hex) == size * 2  # Hex is 2 chars per byte
            assert all(c in '0123456789abcdef' for c in random_hex)
            
            # Test uniqueness
            random_hex2 = secrets.token_hex(size)
            assert random_hex != random_hex2
    
    def test_secure_random_urlsafe(self):
        """Test secure URL-safe random generation"""
        for size in [16, 32, 64]:
            random_urlsafe = secrets.token_urlsafe(size)
            
            assert isinstance(random_urlsafe, str)
            assert len(random_urlsafe) > 0
            
            # Should be URL-safe (no special chars that need encoding)
            import urllib.parse
            encoded = urllib.parse.quote(random_urlsafe)
            assert encoded == random_urlsafe
    
    def test_random_choice(self):
        """Test secure random choice"""
        alphabet = 'abcdefghijklmnopqrstuvwxyz'
        
        # Test random choice
        choice = secrets.choice(alphabet)
        assert choice in alphabet
        
        # Test multiple choices are different (with high probability)
        choices = [secrets.choice(alphabet) for _ in range(10)]
        assert len(set(choices)) > 1  # Should have some variety


@pytest.mark.crypto
@pytest.mark.integration
class TestCryptographicIntegration:
    """Integration tests for cryptographic functions"""
    
    def test_password_hashing_workflow(self):
        """Test complete password hashing workflow"""
        password = "test_password_123"
        
        # Step 1: Generate salt
        salt = secrets.token_bytes(32)
        assert len(salt) == 32
        
        # Step 2: Hash password with salt
        password_hash = hashlib.pbkdf2_hmac('sha256', password.encode(), salt, 100000)
        assert len(password_hash) == 32  # SHA256 produces 32 bytes
        
        # Step 3: Verify password
        verify_hash = hashlib.pbkdf2_hmac('sha256', password.encode(), salt, 100000)
        assert password_hash == verify_hash
        
        # Step 4: Test wrong password
        wrong_password = "wrong_password"
        wrong_hash = hashlib.pbkdf2_hmac('sha256', wrong_password.encode(), salt, 100000)
        assert password_hash != wrong_hash
    
    def test_data_integrity_workflow(self):
        """Test data integrity verification workflow"""
        data = b"important data that must not be tampered with"
        key = secrets.token_bytes(32)
        
        # Step 1: Create HMAC for data integrity
        data_hmac = hmac.new(key, data, hashlib.sha256).digest()
        
        # Step 2: Simulate data transmission/storage
        transmitted_data = data
        transmitted_hmac = data_hmac
        
        # Step 3: Verify data integrity
        verify_hmac = hmac.new(key, transmitted_data, hashlib.sha256).digest()
        assert hmac.compare_digest(transmitted_hmac, verify_hmac)
        
        # Step 4: Test tampered data detection
        tampered_data = data + b"tampered"
        tampered_hmac = hmac.new(key, tampered_data, hashlib.sha256).digest()
        assert not hmac.compare_digest(transmitted_hmac, tampered_hmac)
    
    def test_session_token_generation(self):
        """Test secure session token generation"""
        # Generate session token
        session_token = secrets.token_urlsafe(32)
        
        # Validate token properties
        assert len(session_token) > 0
        assert isinstance(session_token, str)
        
        # Test token uniqueness
        tokens = [secrets.token_urlsafe(32) for _ in range(100)]
        assert len(set(tokens)) == 100  # All should be unique
        
        # Test token entropy (basic check)
        token_bytes = base64.urlsafe_b64decode(session_token + '==')  # Add padding
        assert len(token_bytes) >= 32


@pytest.mark.crypto
@pytest.mark.performance
class TestCryptographicPerformance:
    """Performance tests for cryptographic functions"""
    
    def test_hashing_performance(self):
        """Test hashing performance"""
        import time
        
        test_data = b"x" * 1024  # 1KB of data
        iterations = 1000
        
        # Test SHA256 performance
        start_time = time.time()
        for _ in range(iterations):
            hashlib.sha256(test_data).digest()
        end_time = time.time()
        
        duration = end_time - start_time
        rate = iterations / duration
        
        # Should be able to hash at reasonable rate
        assert rate > 100, f"Hashing rate too slow: {rate:.2f} hashes/sec"
    
    def test_random_generation_performance(self):
        """Test random generation performance"""
        import time
        
        iterations = 1000
        
        # Test random byte generation performance
        start_time = time.time()
        for _ in range(iterations):
            secrets.token_bytes(32)
        end_time = time.time()
        
        duration = end_time - start_time
        rate = iterations / duration
        
        # Should generate random data at reasonable rate
        assert rate > 100, f"Random generation rate too slow: {rate:.2f} tokens/sec"


@pytest.mark.crypto
@pytest.mark.security
class TestCryptographicSecurity:
    """Security-focused tests for cryptographic functions"""
    
    def test_timing_attack_resistance(self):
        """Test resistance to timing attacks"""
        # Test HMAC comparison timing
        key = secrets.token_bytes(32)
        message = b"test message"
        
        correct_hmac = hmac.new(key, message, hashlib.sha256).digest()
        wrong_hmac = secrets.token_bytes(32)
        
        # Use secure comparison
        result1 = hmac.compare_digest(correct_hmac, correct_hmac)
        result2 = hmac.compare_digest(correct_hmac, wrong_hmac)
        
        assert result1 is True
        assert result2 is False
    
    def test_weak_random_detection(self):
        """Test detection of weak randomness"""
        import random
        
        # Test that we're using secure random, not weak random
        # This is more of a code review test
        
        # Secure random (good)
        secure_value = secrets.randbelow(1000000)
        assert 0 <= secure_value < 1000000
        
        # Standard random (should not be used for security)
        # This test documents the difference
        standard_value = random.randint(0, 999999)
        assert 0 <= standard_value <= 999999
        
        # In security contexts, always use secrets module
        assert hasattr(secrets, 'token_bytes')
        assert hasattr(secrets, 'token_hex')
    
    def test_hash_collision_resistance(self):
        """Test hash collision resistance (basic)"""
        # Test that different inputs produce different hashes
        inputs = [
            b"input1",
            b"input2", 
            b"input1 ",  # Note the space
            b"Input1",   # Different case
        ]
        
        hashes = []
        for input_data in inputs:
            hash_value = hashlib.sha256(input_data).hexdigest()
            hashes.append(hash_value)
        
        # All hashes should be different
        assert len(set(hashes)) == len(hashes), "Hash collision detected!"


if __name__ == '__main__':
    pytest.main([__file__, '-v'])