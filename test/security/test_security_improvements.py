"""
Comprehensive security tests for the improved Metasploit Framework components.

This test suite validates the security improvements implemented across:
- HTTP Client security enhancements
- PostgreSQL Client SQL injection prevention
- SSH Client host key verification and authentication security
- Input validation and sanitization
- Audit logging functionality
"""

import unittest
import tempfile
import os
import sys
from unittest.mock import Mock, patch, MagicMock
import logging

# Add the python_framework to the path
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', '..', 'python_framework'))

from helpers.http_client import HttpClient, SSLWarningManager
from helpers.postgres_client import PostgreSQLClient
from helpers.ssh_client import SSHClient, SecureHostKeyPolicy


class TestHttpClientSecurity(unittest.TestCase):
    """Test HTTP client security improvements"""
    
    def setUp(self):
        """Set up test fixtures"""
        self.client = HttpClient(
            base_url="https://example.com",
            verify_ssl=True,
            verbose=True,
            enable_rate_limiting=True
        )
    
    def test_ssl_verification_enabled_by_default(self):
        """Test that SSL verification is enabled by default"""
        client = HttpClient()
        self.assertTrue(client.verify_ssl)
    
    def test_invalid_url_validation(self):
        """Test URL validation prevents malicious URLs"""
        with self.assertRaises(ValueError):
            HttpClient(base_url="javascript:alert('xss')")
        
        with self.assertRaises(ValueError):
            HttpClient(base_url="ftp://malicious.com")
    
    def test_timeout_validation(self):
        """Test timeout parameter validation"""
        with self.assertRaises(ValueError):
            HttpClient(timeout=0)
        
        with self.assertRaises(ValueError):
            HttpClient(timeout=400)  # Too high
    
    def test_header_sanitization(self):
        """Test header value sanitization"""
        sanitized = self.client._sanitize_header_value("test\r\nInjection: malicious")
        self.assertNotIn('\r', sanitized)
        self.assertNotIn('\n', sanitized)
    
    def test_rate_limiting(self):
        """Test rate limiting functionality"""
        # Simulate rapid requests
        for _ in range(self.client.RATE_LIMIT_REQUESTS + 1):
            self.client._request_times.append(0)  # All at time 0
        
        self.assertFalse(self.client._check_rate_limit())
    
    def test_url_building_with_sanitization(self):
        """Test URL building with path sanitization"""
        url = self.client._build_url("/test path with spaces")
        self.assertIn("%20", url)  # Spaces should be encoded
    
    def test_proxy_validation(self):
        """Test proxy configuration validation"""
        valid_proxy = {"http": "http://proxy.example.com:8080"}
        validated = self.client._validate_proxy_config(valid_proxy)
        self.assertEqual(validated, valid_proxy)
        
        invalid_proxy = {"http": "invalid-url"}
        validated = self.client._validate_proxy_config(invalid_proxy)
        self.assertEqual(validated, {})
    
    @patch('requests.Session.request')
    def test_request_validation(self, mock_request):
        """Test request method validation"""
        mock_response = Mock()
        mock_response.status_code = 200
        mock_response.headers = {}
        mock_request.return_value = mock_response
        
        # Valid method should work
        self.client.request('GET', '/test')
        
        # Invalid method should raise error
        with self.assertRaises(ValueError):
            self.client.request('INVALID', '/test')
    
    def test_ssl_warning_manager(self):
        """Test SSL warning management"""
        # Test that warnings can be disabled and enabled
        SSLWarningManager.disable_warnings()
        SSLWarningManager.enable_warnings()
        # No exceptions should be raised


class TestPostgreSQLClientSecurity(unittest.TestCase):
    """Test PostgreSQL client security improvements"""
    
    def setUp(self):
        """Set up test fixtures"""
        # Create client with secure defaults
        self.client = PostgreSQLClient(
            host="localhost",
            database="test",
            username="testuser",
            password="testpass",
            ssl_mode="require",
            enable_audit_log=True
        )
    
    def test_input_validation(self):
        """Test input parameter validation"""
        with self.assertRaises(ValueError):
            PostgreSQLClient(host="")  # Empty host
        
        with self.assertRaises(ValueError):
            PostgreSQLClient(host="localhost", port=0)  # Invalid port
        
        with self.assertRaises(ValueError):
            PostgreSQLClient(host="localhost", username="")  # Empty username
        
        with self.assertRaises(ValueError):
            PostgreSQLClient(host="localhost", ssl_mode="invalid")  # Invalid SSL mode
    
    def test_host_format_validation(self):
        """Test host format validation prevents injection"""
        with self.assertRaises(ValueError):
            PostgreSQLClient(host="localhost; DROP TABLE users;")
        
        with self.assertRaises(ValueError):
            PostgreSQLClient(host="localhost\nmalicious")
    
    def test_query_validation(self):
        """Test SQL query validation"""
        # Valid query should pass
        self.assertTrue(self.client._validate_query("SELECT * FROM users WHERE id = %s"))
        
        # Empty query should fail
        self.assertFalse(self.client._validate_query(""))
        
        # Too long query should fail
        long_query = "SELECT * FROM users WHERE " + "x" * self.client.MAX_QUERY_LENGTH
        self.assertFalse(self.client._validate_query(long_query))
    
    def test_dangerous_pattern_detection(self):
        """Test detection of dangerous SQL patterns"""
        # Create client in non-verbose mode (production mode)
        client = PostgreSQLClient(
            host="localhost",
            database="test", 
            username="testuser",
            password="testpass",
            verbose=False
        )
        
        # These should trigger warnings but not block (for exploit context)
        with patch.object(client.logger, 'warning') as mock_warning:
            client._validate_query("DROP TABLE users")
            mock_warning.assert_called()
    
    def test_secure_connection_params(self):
        """Test secure connection parameter generation"""
        params = self.client._create_connection_params()
        
        self.assertEqual(params['sslmode'], 'require')
        self.assertEqual(params['application_name'], 'Metasploit-Python-Framework')
        self.assertIn('connect_timeout', params)
    
    def test_audit_logging(self):
        """Test audit logging functionality"""
        with patch.object(self.client, 'audit_logger') as mock_logger:
            self.client._audit_log("TEST_ACTION", query="SELECT 1", result="SUCCESS")
            mock_logger.info.assert_called_once()


class TestSSHClientSecurity(unittest.TestCase):
    """Test SSH client security improvements"""
    
    def setUp(self):
        """Set up test fixtures"""
        self.client = SSHClient(
            hostname="localhost",
            username="testuser",
            password="testpass",
            host_key_policy="strict",
            enable_audit_log=True
        )
    
    def test_input_validation(self):
        """Test input parameter validation"""
        with self.assertRaises(ValueError):
            SSHClient(hostname="")  # Empty hostname
        
        with self.assertRaises(ValueError):
            SSHClient(hostname="localhost", port=0)  # Invalid port
        
        with self.assertRaises(ValueError):
            SSHClient(hostname="localhost", username="")  # Empty username
        
        with self.assertRaises(ValueError):
            SSHClient(hostname="localhost", username="test", host_key_policy="invalid")
    
    def test_hostname_format_validation(self):
        """Test hostname format validation"""
        with self.assertRaises(ValueError):
            SSHClient(hostname="localhost; rm -rf /")
        
        with self.assertRaises(ValueError):
            SSHClient(hostname="localhost\nmalicious")
    
    def test_command_validation(self):
        """Test command validation"""
        # Valid command should pass
        self.assertTrue(self.client._validate_command("ls -la"))
        
        # Empty command should fail
        self.assertFalse(self.client._validate_command(""))
        
        # Too long command should fail
        long_command = "echo " + "x" * self.client.MAX_COMMAND_LENGTH
        self.assertFalse(self.client._validate_command(long_command))
    
    def test_dangerous_command_detection(self):
        """Test detection of dangerous commands"""
        with patch.object(self.client.logger, 'warning') as mock_warning:
            self.client._validate_command("rm -rf /")
            mock_warning.assert_called()
    
    def test_output_sanitization(self):
        """Test output sanitization"""
        malicious_output = "test\x00\x01\x02output"
        sanitized = self.client._sanitize_output(malicious_output)
        
        # Control characters should be removed
        self.assertNotIn('\x00', sanitized)
        self.assertNotIn('\x01', sanitized)
        self.assertNotIn('\x02', sanitized)
        self.assertIn('testoutput', sanitized)
    
    def test_output_size_limiting(self):
        """Test output size limiting"""
        large_output = "x" * (self.client.MAX_OUTPUT_SIZE + 1000)
        sanitized = self.client._sanitize_output(large_output)
        
        self.assertLess(len(sanitized), len(large_output))
        self.assertIn("[OUTPUT TRUNCATED]", sanitized)
    
    def test_secure_host_key_policy(self):
        """Test secure host key policy"""
        with tempfile.NamedTemporaryFile(mode='w', delete=False) as f:
            known_hosts_file = f.name
        
        try:
            policy = SecureHostKeyPolicy(
                known_hosts_file=known_hosts_file,
                auto_add=False
            )
            
            # Mock objects for testing
            mock_client = Mock()
            mock_key = Mock()
            mock_key.get_name.return_value = "ssh-rsa"
            mock_key.get_base64.return_value = "AAAAB3NzaC1yc2EAAAA"
            
            # Should raise exception for unknown key when auto_add=False
            with self.assertRaises(Exception):
                policy.missing_host_key(mock_client, "unknown.host", mock_key)
        
        finally:
            os.unlink(known_hosts_file)
    
    def test_audit_logging(self):
        """Test audit logging functionality"""
        with patch.object(self.client, 'audit_logger') as mock_logger:
            self.client._audit_log("TEST_ACTION", command="ls", result="SUCCESS")
            mock_logger.info.assert_called_once()


class TestSecurityIntegration(unittest.TestCase):
    """Integration tests for security features"""
    
    def test_logging_configuration(self):
        """Test that security logging is properly configured"""
        # Test HTTP client logging
        http_client = HttpClient(verbose=True)
        self.assertIsNotNone(http_client.logger)
        
        # Test PostgreSQL client logging
        pg_client = PostgreSQLClient(
            host="localhost",
            username="test",
            password="test",
            enable_audit_log=True
        )
        self.assertIsNotNone(pg_client.logger)
        self.assertIsNotNone(pg_client.audit_logger)
        
        # Test SSH client logging
        ssh_client = SSHClient(
            hostname="localhost",
            username="test",
            password="test",
            enable_audit_log=True
        )
        self.assertIsNotNone(ssh_client.logger)
        self.assertIsNotNone(ssh_client.audit_logger)
    
    def test_error_handling(self):
        """Test proper error handling across components"""
        # HTTP client should handle invalid URLs gracefully
        with self.assertRaises(ValueError):
            HttpClient(base_url="invalid://url")
        
        # PostgreSQL client should handle invalid parameters gracefully
        with self.assertRaises(ValueError):
            PostgreSQLClient(host="", username="test")
        
        # SSH client should handle invalid parameters gracefully
        with self.assertRaises(ValueError):
            SSHClient(hostname="", username="test")
    
    def test_secure_defaults(self):
        """Test that secure defaults are used"""
        # HTTP client should verify SSL by default
        http_client = HttpClient()
        self.assertTrue(http_client.verify_ssl)
        
        # PostgreSQL client should require SSL by default
        pg_client = PostgreSQLClient(host="localhost", username="test", password="test")
        self.assertEqual(pg_client.ssl_mode, "require")
        
        # SSH client should use strict host key policy by default
        ssh_client = SSHClient(hostname="localhost", username="test", password="test")
        self.assertEqual(ssh_client.host_key_policy, "strict")


if __name__ == '__main__':
    # Configure logging for tests
    logging.basicConfig(
        level=logging.DEBUG,
        format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
    )
    
    # Run the tests
    unittest.main(verbosity=2)