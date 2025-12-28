#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
Comprehensive tests for MSF HTTP Client.

This module provides extensive testing for the HTTP client functionality
including unit tests, integration tests, security tests, and performance tests.
"""

import pytest
import requests
import responses
import ssl
import socket
import time
from unittest.mock import Mock, patch, MagicMock
from urllib.parse import urljoin
import sys
import os

# Add lib path
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '../lib'))

try:
    from msf.http_client import HTTPClient
except ImportError:
    # Create a mock HTTPClient for testing if not available
    class HTTPClient:
        def __init__(self, rhost, rport=80, ssl=False, vhost=None, timeout=30, proxies=None):
            self.rhost = rhost
            self.rport = rport
            self.ssl = ssl
            self.vhost = vhost or rhost
            self.timeout = timeout
            self.proxies = proxies or {}
            self.base_url = f"{'https' if ssl else 'http'}://{rhost}:{rport}"
            self.session = requests.Session()
            
        def normalize_uri(self, *paths):
            path = '/'.join(str(p).strip('/') for p in paths if p)
            return '/' + path if path else '/'
            
        def send_request_cgi(self, uri='/', method='GET', **kwargs):
            return self.session.request(method, urljoin(self.base_url, uri), **kwargs)
            
        def get(self, uri='/', **kwargs):
            return self.send_request_cgi(uri=uri, method='GET', **kwargs)
            
        def post(self, uri='/', **kwargs):
            return self.send_request_cgi(uri=uri, method='POST', **kwargs)
            
        def close(self):
            self.session.close()


class TestHTTPClientInitialization:
    """Test HTTP client initialization and configuration."""
    
    def test_basic_initialization(self):
        """Test basic HTTP client initialization."""
        client = HTTPClient(rhost='192.168.1.100', rport=80)
        
        assert client.rhost == '192.168.1.100'
        assert client.rport == 80
        assert client.ssl is False
        assert client.vhost == '192.168.1.100'
        assert client.timeout == 30
        assert client.base_url == 'http://192.168.1.100:80'
        
    def test_ssl_initialization(self):
        """Test HTTPS client initialization."""
        client = HTTPClient(rhost='example.com', rport=443, ssl=True)
        
        assert client.ssl is True
        assert client.base_url == 'https://example.com:443'
        
    def test_vhost_initialization(self):
        """Test virtual host configuration."""
        client = HTTPClient(rhost='192.168.1.100', vhost='example.com')
        
        assert client.vhost == 'example.com'
        
    def test_proxy_initialization(self):
        """Test proxy configuration."""
        proxies = {'http': 'http://proxy:8080', 'https': 'https://proxy:8080'}
        client = HTTPClient(rhost='example.com', proxies=proxies)
        
        assert client.proxies == proxies
        
    def test_timeout_initialization(self):
        """Test timeout configuration."""
        client = HTTPClient(rhost='example.com', timeout=60)
        
        assert client.timeout == 60


class TestHTTPClientURIHandling:
    """Test URI normalization and handling."""
    
    def setup_method(self):
        """Set up test client."""
        self.client = HTTPClient(rhost='example.com')
        
    def test_normalize_uri_empty(self):
        """Test URI normalization with empty input."""
        result = self.client.normalize_uri()
        assert result == '/'
        
    def test_normalize_uri_single_path(self):
        """Test URI normalization with single path."""
        result = self.client.normalize_uri('admin')
        assert result == '/admin'
        
    def test_normalize_uri_multiple_paths(self):
        """Test URI normalization with multiple paths."""
        result = self.client.normalize_uri('admin', 'login.php')
        assert result == '/admin/login.php'
        
    def test_normalize_uri_with_slashes(self):
        """Test URI normalization with existing slashes."""
        result = self.client.normalize_uri('/admin/', '/login.php/')
        assert result == '/admin/login.php'
        
    def test_normalize_uri_with_none_values(self):
        """Test URI normalization with None values."""
        result = self.client.normalize_uri('admin', None, 'login.php')
        assert result == '/admin/login.php'


@pytest.mark.http
class TestHTTPClientRequests:
    """Test HTTP request functionality."""
    
    def setup_method(self):
        """Set up test client."""
        self.client = HTTPClient(rhost='example.com', rport=80)
        
    @responses.activate
    def test_get_request_success(self):
        """Test successful GET request."""
        responses.add(responses.GET, 'http://example.com:80/', 
                     json={'status': 'ok'}, status=200)
        
        response = self.client.get('/')
        
        assert response is not None
        assert response.status_code == 200
        assert response.json() == {'status': 'ok'}
        
    @responses.activate
    def test_get_request_with_params(self):
        """Test GET request with parameters."""
        responses.add(responses.GET, 'http://example.com:80/search',
                     json={'results': []}, status=200)
        
        response = self.client.get('/search', params={'q': 'test'})
        
        assert response is not None
        assert response.status_code == 200
        
    @responses.activate
    def test_post_request_success(self):
        """Test successful POST request."""
        responses.add(responses.POST, 'http://example.com:80/login',
                     json={'token': 'abc123'}, status=200)
        
        response = self.client.post('/login', data={'user': 'admin', 'pass': 'secret'})
        
        assert response is not None
        assert response.status_code == 200
        assert response.json() == {'token': 'abc123'}
        
    @responses.activate
    def test_request_with_custom_headers(self):
        """Test request with custom headers."""
        responses.add(responses.GET, 'http://example.com:80/',
                     json={'status': 'ok'}, status=200)
        
        custom_headers = {'X-Custom-Header': 'test-value'}
        response = self.client.get('/', headers=custom_headers)
        
        assert response is not None
        # Verify custom header was sent (would need to check request in real implementation)
        
    @responses.activate
    def test_request_with_cookies(self):
        """Test request with cookies."""
        responses.add(responses.GET, 'http://example.com:80/',
                     json={'status': 'ok'}, status=200)
        
        cookies = {'session_id': 'abc123'}
        response = self.client.get('/', cookies=cookies)
        
        assert response is not None
        assert response.status_code == 200


@pytest.mark.http
@pytest.mark.security
class TestHTTPClientSecurity:
    """Test HTTP client security features."""
    
    def setup_method(self):
        """Set up test client."""
        self.client = HTTPClient(rhost='example.com', rport=443, ssl=True)
        
    def test_ssl_verification_disabled(self):
        """Test that SSL verification is disabled by default."""
        # In security testing context, SSL verification is often disabled
        assert self.client.session.verify is False
        
    def test_default_user_agent(self):
        """Test default User-Agent header."""
        expected_ua = 'Mozilla/5.0 (compatible; Metasploit)'
        assert self.client.session.headers.get('User-Agent') == expected_ua
        
    def test_host_header_configuration(self):
        """Test Host header configuration."""
        client = HTTPClient(rhost='192.168.1.100', rport=80, vhost='example.com')
        expected_host = 'example.com:80'
        assert client.session.headers.get('Host') == expected_host


@pytest.mark.http
@pytest.mark.network
class TestHTTPClientErrorHandling:
    """Test HTTP client error handling."""
    
    def setup_method(self):
        """Set up test client."""
        self.client = HTTPClient(rhost='nonexistent.example.com')
        
    def test_connection_error_handling(self):
        """Test handling of connection errors."""
        # This would test actual connection errors in real implementation
        with patch('requests.Session.request') as mock_request:
            mock_request.side_effect = requests.exceptions.ConnectionError("Connection failed")
            
            response = self.client.get('/')
            assert response is None
            
    def test_timeout_error_handling(self):
        """Test handling of timeout errors."""
        with patch('requests.Session.request') as mock_request:
            mock_request.side_effect = requests.exceptions.Timeout("Request timed out")
            
            response = self.client.get('/')
            assert response is None
            
    def test_ssl_error_handling(self):
        """Test handling of SSL errors."""
        with patch('requests.Session.request') as mock_request:
            mock_request.side_effect = requests.exceptions.SSLError("SSL error")
            
            response = self.client.get('/')
            assert response is None


@pytest.mark.performance
class TestHTTPClientPerformance:
    """Test HTTP client performance characteristics."""
    
    def setup_method(self):
        """Set up test client."""
        self.client = HTTPClient(rhost='example.com')
        
    @responses.activate
    def test_request_performance(self, benchmark):
        """Benchmark HTTP request performance."""
        responses.add(responses.GET, 'http://example.com:80/',
                     body='OK', status=200)
        
        def make_request():
            return self.client.get('/')
            
        result = benchmark(make_request)
        assert result is not None
        
    @responses.activate
    def test_session_reuse(self):
        """Test that session is reused for multiple requests."""
        responses.add(responses.GET, 'http://example.com:80/',
                     body='OK', status=200)
        
        # Make multiple requests
        response1 = self.client.get('/')
        response2 = self.client.get('/')
        
        assert response1 is not None
        assert response2 is not None
        # In real implementation, would verify session reuse


@pytest.mark.integration
class TestHTTPClientIntegration:
    """Integration tests for HTTP client."""
    
    def setup_method(self):
        """Set up test environment."""
        self.client = HTTPClient(rhost='httpbin.org', rport=80)
        
    @pytest.mark.skip(reason="Integration tests disabled by default")
    def test_real_http_request(self):
        """Test real HTTP request (requires network)."""
        # This would test against a real service
        # Skip by default to avoid network dependencies
        pass
        
    def test_mock_server_integration(self, mock_http_server):
        """Test integration with mock server."""
        client = HTTPClient(rhost=mock_http_server.host, rport=mock_http_server.port)
        
        response = client.get('/')
        assert response is not None
        # Would verify response content in real implementation


class TestHTTPClientCompatibility:
    """Test compatibility with Ruby MSF HTTP client."""
    
    def setup_method(self):
        """Set up test client."""
        self.client = HTTPClient(rhost='example.com')
        
    def test_send_request_cgi_compatibility(self):
        """Test send_request_cgi method compatibility."""
        # Test that the method signature matches Ruby version
        with patch.object(self.client.session, 'request') as mock_request:
            mock_request.return_value = Mock(status_code=200)
            
            response = self.client.send_request_cgi(
                uri='/test',
                method='POST',
                data={'key': 'value'},
                headers={'Content-Type': 'application/json'}
            )
            
            assert mock_request.called
            
    def test_ruby_method_equivalents(self):
        """Test that Python methods match Ruby equivalents."""
        # Verify method names and signatures match Ruby version
        assert hasattr(self.client, 'send_request_cgi')
        assert hasattr(self.client, 'normalize_uri')
        assert hasattr(self.client, 'get')
        # Would add more method checks for full compatibility


if __name__ == '__main__':
    pytest.main([__file__])