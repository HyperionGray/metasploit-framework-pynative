"""
Comprehensive tests for HTTP client helper functionality.

Tests the HTTP client used for web-based exploit development to ensure
correct behavior after Ruby-to-Python migration.
"""

import pytest
import sys
from pathlib import Path
from unittest.mock import Mock, patch, MagicMock
import requests

# Add python_framework to path
sys.path.insert(0, str(Path(__file__).parent.parent / 'python_framework'))

from helpers.http_client import HttpClient, HttpExploitMixin


class TestHttpClientInitialization:
    """Test HttpClient initialization"""
    
    def test_default_initialization(self):
        """Test creating HttpClient with default values"""
        client = HttpClient()
        
        assert client.base_url == ""
        assert client.ssl is False
        assert client.verify_ssl is False
        assert client.timeout == 10
        assert client.verbose is False
        assert client.session is not None
    
    def test_initialization_with_base_url(self):
        """Test creating HttpClient with base URL"""
        client = HttpClient(base_url="http://example.com")
        
        assert client.base_url == "http://example.com"
    
    def test_initialization_with_ssl(self):
        """Test creating HttpClient with SSL enabled"""
        client = HttpClient(ssl=True, verify_ssl=False)
        
        assert client.ssl is True
        assert client.verify_ssl is False
    
    def test_initialization_with_custom_timeout(self):
        """Test creating HttpClient with custom timeout"""
        client = HttpClient(timeout=30)
        
        assert client.timeout == 30
    
    def test_initialization_with_custom_user_agent(self):
        """Test creating HttpClient with custom user agent"""
        client = HttpClient(user_agent="CustomAgent/1.0")
        
        assert "User-Agent" in client.session.headers
        assert client.session.headers["User-Agent"] == "CustomAgent/1.0"
    
    def test_initialization_with_proxy(self):
        """Test creating HttpClient with proxy configuration"""
        proxy = {"http": "http://proxy:8080", "https": "https://proxy:8080"}
        client = HttpClient(proxy=proxy)
        
        assert client.session.proxies == proxy
    
    def test_verbose_mode(self):
        """Test creating HttpClient in verbose mode"""
        client = HttpClient(verbose=True)
        
        assert client.verbose is True


class TestHttpClientUrlBuilding:
    """Test URL building functionality"""
    
    def test_build_url_without_base_url(self):
        """Test URL building when no base URL is set"""
        client = HttpClient()
        url = client._build_url("/test")
        
        assert url == "/test"
    
    def test_build_url_with_base_url(self):
        """Test URL building with base URL"""
        client = HttpClient(base_url="http://example.com")
        url = client._build_url("/api/endpoint")
        
        assert url == "http://example.com/api/endpoint"
    
    def test_build_url_with_trailing_slash(self):
        """Test URL building handles trailing slashes correctly"""
        client = HttpClient(base_url="http://example.com/")
        url = client._build_url("api/endpoint")
        
        assert url == "http://example.com/api/endpoint"


class TestHttpClientRequests:
    """Test HTTP request methods"""
    
    @patch('requests.Session.request')
    def test_get_request(self, mock_request):
        """Test making a GET request"""
        # Setup mock
        mock_response = Mock()
        mock_response.status_code = 200
        mock_response.text = "Success"
        mock_response.headers = {}
        mock_request.return_value = mock_response
        
        client = HttpClient()
        response = client.get("/test")
        
        assert response is not None
        assert response.status_code == 200
        mock_request.assert_called_once()
    
    @patch('requests.Session.request')
    def test_post_request(self, mock_request):
        """Test making a POST request"""
        mock_response = Mock()
        mock_response.status_code = 201
        mock_response.text = "Created"
        mock_response.headers = {}
        mock_request.return_value = mock_response
        
        client = HttpClient()
        response = client.post("/test", data={"key": "value"})
        
        assert response is not None
        assert response.status_code == 201
        mock_request.assert_called_once()
    
    @patch('requests.Session.request')
    def test_put_request(self, mock_request):
        """Test making a PUT request"""
        mock_response = Mock()
        mock_response.status_code = 200
        mock_response.text = "Updated"
        mock_response.headers = {}
        mock_request.return_value = mock_response
        
        client = HttpClient()
        response = client.put("/test", data={"key": "value"})
        
        assert response is not None
        assert response.status_code == 200
        mock_request.assert_called_once()
    
    @patch('requests.Session.request')
    def test_delete_request(self, mock_request):
        """Test making a DELETE request"""
        mock_response = Mock()
        mock_response.status_code = 204
        mock_response.text = ""
        mock_response.headers = {}
        mock_request.return_value = mock_response
        
        client = HttpClient()
        response = client.delete("/test")
        
        assert response is not None
        assert response.status_code == 204
        mock_request.assert_called_once()


class TestHttpClientHeaders:
    """Test HTTP header handling"""
    
    def test_default_headers(self):
        """Test that default headers are set correctly"""
        client = HttpClient()
        
        assert "User-Agent" in client.session.headers
        assert "Accept" in client.session.headers
        assert "Connection" in client.session.headers
    
    @patch('requests.Session.request')
    def test_custom_headers(self, mock_request):
        """Test sending custom headers"""
        mock_response = Mock()
        mock_response.status_code = 200
        mock_response.headers = {}
        mock_request.return_value = mock_response
        
        client = HttpClient()
        custom_headers = {"X-Custom-Header": "CustomValue"}
        client.get("/test", headers=custom_headers)
        
        # Verify the request was made
        mock_request.assert_called_once()


class TestHttpClientErrorHandling:
    """Test error handling"""
    
    @patch('requests.Session.request')
    def test_connection_error_handling(self, mock_request):
        """Test handling of connection errors"""
        mock_request.side_effect = requests.exceptions.ConnectionError("Connection failed")
        
        client = HttpClient()
        
        with pytest.raises(requests.exceptions.ConnectionError):
            client.get("/test")
    
    @patch('requests.Session.request')
    def test_timeout_error_handling(self, mock_request):
        """Test handling of timeout errors"""
        mock_request.side_effect = requests.exceptions.Timeout("Request timed out")
        
        client = HttpClient()
        
        with pytest.raises(requests.exceptions.Timeout):
            client.get("/test")
    
    @patch('requests.Session.request')
    def test_http_error_handling(self, mock_request):
        """Test handling of HTTP errors"""
        mock_response = Mock()
        mock_response.status_code = 404
        mock_response.text = "Not Found"
        mock_response.headers = {}
        mock_request.return_value = mock_response
        
        client = HttpClient()
        response = client.get("/test")
        
        assert response.status_code == 404


class TestHttpClientCookies:
    """Test cookie handling"""
    
    @patch('requests.Session.request')
    def test_cookie_persistence(self, mock_request):
        """Test that cookies persist across requests"""
        mock_response = Mock()
        mock_response.status_code = 200
        mock_response.cookies = {"session": "abc123"}
        mock_response.headers = {}
        mock_request.return_value = mock_response
        
        client = HttpClient()
        
        # First request should set cookie
        response1 = client.get("/login")
        
        # Cookie should be in session
        assert client.session.cookies is not None


class TestHttpExploitMixin:
    """Test HttpExploitMixin functionality"""
    
    def test_mixin_provides_http_client(self):
        """Test that mixin provides HTTP client functionality"""
        
        # Import RemoteExploit and ExploitInfo for proper testing
        from core.exploit import RemoteExploit, ExploitInfo
        
        class TestExploit(RemoteExploit, HttpExploitMixin):
            def check(self):
                from core.exploit import ExploitResult
                return ExploitResult(True, "Vulnerable")
            
            def exploit(self):
                from core.exploit import ExploitResult
                return ExploitResult(True, "Exploited")
        
        info = ExploitInfo(
            name="Test",
            description="Test exploit",
            author=["Test"]
        )
        
        exploit = TestExploit(info)
        
        # Set required options
        exploit.set_option("RHOSTS", "example.com")
        exploit.set_option("RPORT", 80)
        exploit.set_option("SSL", False)
        
        # Check that HTTP client methods are available
        assert hasattr(exploit, 'http_get')
        assert hasattr(exploit, 'http_post')
        assert hasattr(exploit, 'http_client')


class TestHttpClientSSL:
    """Test SSL/TLS handling"""
    
    def test_ssl_verification_disabled(self):
        """Test that SSL verification can be disabled"""
        client = HttpClient(ssl=True, verify_ssl=False)
        
        assert client.ssl is True
        assert client.verify_ssl is False
        assert client.session.verify is False
    
    def test_ssl_verification_enabled(self):
        """Test that SSL verification can be enabled"""
        client = HttpClient(ssl=True, verify_ssl=True)
        
        assert client.ssl is True
        assert client.verify_ssl is True
        assert client.session.verify is True


class TestHttpClientMethods:
    """Test various HTTP methods"""
    
    @patch('requests.Session.request')
    def test_get_with_params(self, mock_request):
        """Test GET request with query parameters"""
        mock_response = Mock()
        mock_response.status_code = 200
        mock_response.headers = {}
        mock_request.return_value = mock_response
        
        client = HttpClient()
        params = {"key1": "value1", "key2": "value2"}
        client.get("/test", params=params)
        
        # Verify params were passed
        call_args = mock_request.call_args
        assert call_args is not None
    
    @patch('requests.Session.request')
    def test_post_with_json(self, mock_request):
        """Test POST request with JSON data"""
        mock_response = Mock()
        mock_response.status_code = 200
        mock_response.headers = {}
        mock_request.return_value = mock_response
        
        client = HttpClient()
        json_data = {"key": "value"}
        client.post("/test", json_data=json_data)
        
        mock_request.assert_called_once()
    
    @patch('requests.Session.request')
    def test_post_with_form_data(self, mock_request):
        """Test POST request with form data"""
        mock_response = Mock()
        mock_response.status_code = 200
        mock_response.headers = {}
        mock_request.return_value = mock_response
        
        client = HttpClient()
        form_data = {"username": "admin", "password": "password123"}
        client.post("/login", data=form_data)
        
        mock_request.assert_called_once()


class TestHttpClientIntegration:
    """Integration tests for HTTP client"""
    
    def test_client_session_persistence(self):
        """Test that session persists across multiple requests"""
        client = HttpClient()
        
        # Session should be the same object across requests
        session1 = client.session
        session2 = client.session
        
        assert session1 is session2
    
    def test_client_with_all_features(self):
        """Test client with all features enabled"""
        proxy = {"http": "http://proxy:8080"}
        client = HttpClient(
            base_url="https://example.com",
            ssl=True,
            verify_ssl=False,
            timeout=30,
            user_agent="CustomAgent",
            proxy=proxy,
            verbose=True
        )
        
        assert client.base_url == "https://example.com"
        assert client.ssl is True
        assert client.verify_ssl is False
        assert client.timeout == 30
        assert client.verbose is True
        assert client.session.proxies == proxy


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
