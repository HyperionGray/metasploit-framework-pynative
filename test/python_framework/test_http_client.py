#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
Unit tests for the HttpClient helper.

This test module validates the Python implementation of the HTTP client helper,
ensuring proper HTTP request handling, cookie management, and mixin functionality.
"""

import unittest
from unittest.mock import Mock, MagicMock, patch, call
import requests

from python_framework.helpers.http_client import HttpClient, HttpExploitMixin


class TestHttpClient(unittest.TestCase):
    """Test HttpClient class"""

    def test_initialization_defaults(self):
        """Test HttpClient initialization with default values"""
        client = HttpClient()

        self.assertEqual(client.base_url, "")
        self.assertFalse(client.ssl)
        self.assertFalse(client.verify_ssl)
        self.assertEqual(client.timeout, 10)
        self.assertFalse(client.verbose)
        self.assertIsNotNone(client.session)

    def test_initialization_with_parameters(self):
        """Test HttpClient initialization with custom parameters"""
        client = HttpClient(
            base_url="https://example.com",
            ssl=True,
            verify_ssl=True,
            timeout=30,
            user_agent="CustomAgent/1.0",
            verbose=True,
        )

        self.assertEqual(client.base_url, "https://example.com")
        self.assertTrue(client.ssl)
        self.assertTrue(client.verify_ssl)
        self.assertEqual(client.timeout, 30)
        self.assertTrue(client.verbose)
        self.assertEqual(client.session.headers["User-Agent"], "CustomAgent/1.0")

    def test_initialization_with_proxy(self):
        """Test HttpClient initialization with proxy"""
        proxy = {"http": "http://proxy:8080", "https": "https://proxy:8080"}
        client = HttpClient(proxy=proxy)

        self.assertEqual(client.session.proxies, proxy)

    def test_default_headers_set(self):
        """Test that default headers are set correctly"""
        client = HttpClient()

        self.assertIn("User-Agent", client.session.headers)
        self.assertIn("Accept", client.session.headers)
        self.assertIn("Accept-Language", client.session.headers)
        self.assertIn("Accept-Encoding", client.session.headers)
        self.assertIn("Connection", client.session.headers)

    def test_build_url_with_base_url(self):
        """Test URL building with base URL"""
        client = HttpClient(base_url="https://example.com")

        url = client._build_url("/api/endpoint")
        self.assertEqual(url, "https://example.com/api/endpoint")

    def test_build_url_without_base_url(self):
        """Test URL building without base URL"""
        client = HttpClient()

        url = client._build_url("https://example.com/api/endpoint")
        self.assertEqual(url, "https://example.com/api/endpoint")

    def test_build_url_with_relative_path(self):
        """Test URL building with various relative paths"""
        client = HttpClient(base_url="https://example.com/base")

        # Test various path formats - urljoin behavior
        # Relative path without leading slash appends to base directory
        self.assertIn("example.com", client._build_url("api/test"))
        # Absolute path (starting with /) replaces the path
        self.assertEqual(client._build_url("/api/test"), "https://example.com/api/test")

    @patch("python_framework.helpers.http_client.requests.Session.request")
    def test_request_method_get(self, mock_request):
        """Test HTTP GET request"""
        mock_response = Mock(spec=requests.Response)
        mock_response.status_code = 200
        mock_response.text = "OK"
        mock_response.headers = {}
        mock_request.return_value = mock_response

        client = HttpClient(base_url="https://example.com")
        response = client.get("/test")

        self.assertEqual(response.status_code, 200)
        mock_request.assert_called_once()
        args, kwargs = mock_request.call_args
        self.assertEqual(args[0], "GET")
        self.assertIn("https://example.com/test", args[1])

    @patch("python_framework.helpers.http_client.requests.Session.request")
    def test_request_method_post(self, mock_request):
        """Test HTTP POST request"""
        mock_response = Mock(spec=requests.Response)
        mock_response.status_code = 201
        mock_response.text = "Created"
        mock_response.headers = {}
        mock_request.return_value = mock_response

        client = HttpClient(base_url="https://example.com")
        response = client.post("/test", data={"key": "value"})

        self.assertEqual(response.status_code, 201)
        mock_request.assert_called_once()
        args, kwargs = mock_request.call_args
        self.assertEqual(args[0], "POST")
        self.assertEqual(kwargs["data"], {"key": "value"})

    @patch("python_framework.helpers.http_client.requests.Session.request")
    def test_request_method_put(self, mock_request):
        """Test HTTP PUT request"""
        mock_response = Mock(spec=requests.Response)
        mock_response.status_code = 200
        mock_response.headers = {}
        mock_request.return_value = mock_response

        client = HttpClient()
        client.put("https://example.com/test")

        mock_request.assert_called_once()
        args, _ = mock_request.call_args
        self.assertEqual(args[0], "PUT")

    @patch("python_framework.helpers.http_client.requests.Session.request")
    def test_request_method_delete(self, mock_request):
        """Test HTTP DELETE request"""
        mock_response = Mock(spec=requests.Response)
        mock_response.status_code = 204
        mock_response.headers = {}
        mock_request.return_value = mock_response

        client = HttpClient()
        client.delete("https://example.com/test")

        mock_request.assert_called_once()
        args, _ = mock_request.call_args
        self.assertEqual(args[0], "DELETE")

    @patch("python_framework.helpers.http_client.requests.Session.request")
    def test_request_method_head(self, mock_request):
        """Test HTTP HEAD request"""
        mock_response = Mock(spec=requests.Response)
        mock_response.status_code = 200
        mock_response.headers = {}
        mock_request.return_value = mock_response

        client = HttpClient()
        client.head("https://example.com/test")

        mock_request.assert_called_once()
        args, _ = mock_request.call_args
        self.assertEqual(args[0], "HEAD")

    @patch("python_framework.helpers.http_client.requests.Session.request")
    def test_request_method_options(self, mock_request):
        """Test HTTP OPTIONS request"""
        mock_response = Mock(spec=requests.Response)
        mock_response.status_code = 200
        mock_response.headers = {}
        mock_request.return_value = mock_response

        client = HttpClient()
        client.options("https://example.com/test")

        mock_request.assert_called_once()
        args, _ = mock_request.call_args
        self.assertEqual(args[0], "OPTIONS")

    @patch("python_framework.helpers.http_client.requests.Session.request")
    def test_request_with_custom_headers(self, mock_request):
        """Test request with custom headers"""
        mock_response = Mock(spec=requests.Response)
        mock_response.status_code = 200
        mock_response.headers = {}
        mock_request.return_value = mock_response

        client = HttpClient()
        custom_headers = {"X-Custom-Header": "CustomValue"}
        client.get("https://example.com/test", headers=custom_headers)

        _, kwargs = mock_request.call_args
        self.assertIn("X-Custom-Header", kwargs["headers"])
        self.assertEqual(kwargs["headers"]["X-Custom-Header"], "CustomValue")

    @patch("python_framework.helpers.http_client.requests.Session.request")
    def test_request_with_params(self, mock_request):
        """Test request with URL parameters"""
        mock_response = Mock(spec=requests.Response)
        mock_response.status_code = 200
        mock_response.headers = {}
        mock_request.return_value = mock_response

        client = HttpClient()
        params = {"key": "value", "foo": "bar"}
        client.get("https://example.com/test", params=params)

        _, kwargs = mock_request.call_args
        self.assertEqual(kwargs["params"], params)

    @patch("python_framework.helpers.http_client.requests.Session.request")
    def test_request_with_json_data(self, mock_request):
        """Test request with JSON data"""
        mock_response = Mock(spec=requests.Response)
        mock_response.status_code = 200
        mock_response.headers = {}
        mock_request.return_value = mock_response

        client = HttpClient()
        json_data = {"key": "value"}
        client.post("https://example.com/test", json_data=json_data)

        _, kwargs = mock_request.call_args
        self.assertEqual(kwargs["json"], json_data)

    @patch("python_framework.helpers.http_client.requests.Session.request")
    def test_request_with_custom_timeout(self, mock_request):
        """Test request with custom timeout"""
        mock_response = Mock(spec=requests.Response)
        mock_response.status_code = 200
        mock_response.headers = {}
        mock_request.return_value = mock_response

        client = HttpClient(timeout=10)
        client.get("https://example.com/test", timeout=30)

        _, kwargs = mock_request.call_args
        self.assertEqual(kwargs["timeout"], 30)

    @patch("python_framework.helpers.http_client.requests.Session.request")
    def test_request_uses_default_timeout(self, mock_request):
        """Test request uses default timeout when not specified"""
        mock_response = Mock(spec=requests.Response)
        mock_response.status_code = 200
        mock_response.headers = {}
        mock_request.return_value = mock_response

        client = HttpClient(timeout=25)
        client.get("https://example.com/test")

        _, kwargs = mock_request.call_args
        self.assertEqual(kwargs["timeout"], 25)

    @patch("python_framework.helpers.http_client.requests.Session.request")
    def test_request_with_allow_redirects(self, mock_request):
        """Test request with redirect control"""
        mock_response = Mock(spec=requests.Response)
        mock_response.status_code = 200
        mock_response.headers = {}
        mock_request.return_value = mock_response

        client = HttpClient()
        client.get("https://example.com/test", allow_redirects=False)

        _, kwargs = mock_request.call_args
        self.assertFalse(kwargs["allow_redirects"])

    @patch("python_framework.helpers.http_client.requests.Session.request")
    def test_request_exception_handling(self, mock_request):
        """Test request exception handling"""
        mock_request.side_effect = requests.exceptions.ConnectionError("Connection failed")

        client = HttpClient()

        with self.assertRaises(requests.exceptions.ConnectionError):
            client.get("https://example.com/test")

    def test_set_cookie(self):
        """Test setting a cookie"""
        client = HttpClient()

        # cookies.set() requires a domain in some versions, so provide one
        client.set_cookie("session_id", "abc123", domain="example.com")

        self.assertEqual(client.get_cookie("session_id"), "abc123")

    def test_set_cookie_with_domain(self):
        """Test setting a cookie with domain"""
        client = HttpClient()

        client.set_cookie("session_id", "abc123", domain="example.com")

        self.assertEqual(client.get_cookie("session_id"), "abc123")

    def test_get_cookie_nonexistent(self):
        """Test getting non-existent cookie returns None"""
        client = HttpClient()

        value = client.get_cookie("nonexistent")

        self.assertIsNone(value)

    def test_clear_cookies(self):
        """Test clearing all cookies"""
        client = HttpClient()

        client.set_cookie("cookie1", "value1", domain="example.com")
        client.set_cookie("cookie2", "value2", domain="example.com")
        client.clear_cookies()

        self.assertIsNone(client.get_cookie("cookie1"))
        self.assertIsNone(client.get_cookie("cookie2"))

    def test_set_header(self):
        """Test setting a custom header"""
        client = HttpClient()

        client.set_header("X-Custom", "Value")

        self.assertEqual(client.session.headers["X-Custom"], "Value")

    def test_remove_header(self):
        """Test removing a header"""
        client = HttpClient()

        client.set_header("X-Custom", "Value")
        client.remove_header("X-Custom")

        self.assertNotIn("X-Custom", client.session.headers)

    def test_remove_nonexistent_header(self):
        """Test removing non-existent header doesn't raise error"""
        client = HttpClient()

        # Should not raise exception
        client.remove_header("NonExistent")

    def test_close_session(self):
        """Test closing the session"""
        client = HttpClient()

        with patch.object(client.session, "close") as mock_close:
            client.close()
            mock_close.assert_called_once()

    @patch("python_framework.helpers.http_client.requests.Session.request")
    def test_verbose_logging_enabled(self, mock_request):
        """Test verbose logging when enabled"""
        mock_response = Mock(spec=requests.Response)
        mock_response.status_code = 200
        mock_response.text = "Response body"
        mock_response.reason = "OK"
        mock_response.headers = {"Content-Type": "text/html"}
        mock_request.return_value = mock_response

        client = HttpClient(verbose=True)

        with patch.object(client.logger, "info") as mock_info:
            client.get("https://example.com/test")
            # Should log request and response
            self.assertTrue(mock_info.called)

    @patch("python_framework.helpers.http_client.requests.Session.request")
    def test_verbose_logging_disabled(self, mock_request):
        """Test verbose logging when disabled"""
        mock_response = Mock(spec=requests.Response)
        mock_response.status_code = 200
        mock_response.text = "Response body"
        mock_response.headers = {}
        mock_request.return_value = mock_response

        client = HttpClient(verbose=False)

        with patch.object(client.logger, "info") as mock_info:
            client.get("https://example.com/test")
            # Should not log when verbose is False
            mock_info.assert_not_called()


class TestHttpExploitMixin(unittest.TestCase):
    """Test HttpExploitMixin class"""

    def setUp(self):
        """Set up test fixtures"""
        # Create a mock exploit class with the mixin
        class MockExploit(HttpExploitMixin):
            def __init__(self):
                self.datastore = {
                    "RHOSTS": "192.168.1.100",
                    "RPORT": 80,
                    "SSL": False,
                    "ConnectTimeout": 10,
                    "VERBOSE": False,
                }
                super().__init__()

            def get_option(self, name, default=None):
                return self.datastore.get(name, default)

        self.exploit_class = MockExploit

    def test_mixin_initialization(self):
        """Test mixin initialization"""
        exploit = self.exploit_class()

        self.assertIsNone(exploit._http_client)

    def test_http_client_lazy_creation(self):
        """Test HTTP client is created on first access"""
        exploit = self.exploit_class()

        client = exploit.http_client

        self.assertIsNotNone(client)
        self.assertIsInstance(client, HttpClient)

    def test_http_client_reuses_instance(self):
        """Test HTTP client reuses same instance"""
        exploit = self.exploit_class()

        client1 = exploit.http_client
        client2 = exploit.http_client

        self.assertIs(client1, client2)

    def test_http_client_uses_exploit_options(self):
        """Test HTTP client uses exploit configuration"""
        exploit = self.exploit_class()
        exploit.datastore["RHOSTS"] = "example.com"
        exploit.datastore["RPORT"] = 443
        exploit.datastore["SSL"] = True

        client = exploit.http_client

        self.assertIn("https://example.com:443", client.base_url)
        self.assertTrue(client.ssl)

    def test_http_client_handles_multiple_hosts(self):
        """Test HTTP client handles comma-separated hosts"""
        exploit = self.exploit_class()
        exploit.datastore["RHOSTS"] = "192.168.1.1, 192.168.1.2, 192.168.1.3"

        client = exploit.http_client

        # Should use first host
        self.assertIn("192.168.1.1", client.base_url)

    @patch("python_framework.helpers.http_client.HttpClient.get")
    def test_http_get_method(self, mock_get):
        """Test http_get convenience method"""
        mock_response = Mock(spec=requests.Response)
        mock_get.return_value = mock_response

        exploit = self.exploit_class()
        response = exploit.http_get("/api/test")

        self.assertEqual(response, mock_response)
        mock_get.assert_called_once_with("/api/test")

    @patch("python_framework.helpers.http_client.HttpClient.post")
    def test_http_post_method(self, mock_post):
        """Test http_post convenience method"""
        mock_response = Mock(spec=requests.Response)
        mock_post.return_value = mock_response

        exploit = self.exploit_class()
        response = exploit.http_post("/api/test", data={"key": "value"})

        self.assertEqual(response, mock_response)
        mock_post.assert_called_once_with("/api/test", data={"key": "value"})

    @patch("python_framework.helpers.http_client.HttpClient.put")
    def test_http_put_method(self, mock_put):
        """Test http_put convenience method"""
        mock_response = Mock(spec=requests.Response)
        mock_put.return_value = mock_response

        exploit = self.exploit_class()
        response = exploit.http_put("/api/test")

        self.assertEqual(response, mock_response)
        mock_put.assert_called_once_with("/api/test")

    @patch("python_framework.helpers.http_client.HttpClient.delete")
    def test_http_delete_method(self, mock_delete):
        """Test http_delete convenience method"""
        mock_response = Mock(spec=requests.Response)
        mock_delete.return_value = mock_response

        exploit = self.exploit_class()
        response = exploit.http_delete("/api/test")

        self.assertEqual(response, mock_response)
        mock_delete.assert_called_once_with("/api/test")

    def test_cleanup_http_with_client(self):
        """Test cleanup_http closes client"""
        exploit = self.exploit_class()
        client = exploit.http_client  # Create client

        with patch.object(client, "close") as mock_close:
            exploit.cleanup_http()
            mock_close.assert_called_once()

        self.assertIsNone(exploit._http_client)

    def test_cleanup_http_without_client(self):
        """Test cleanup_http when no client exists"""
        exploit = self.exploit_class()

        # Should not raise exception
        exploit.cleanup_http()

        self.assertIsNone(exploit._http_client)

    def test_http_client_with_http_scheme(self):
        """Test HTTP client uses HTTP scheme when SSL is False"""
        exploit = self.exploit_class()
        exploit.datastore["SSL"] = False

        client = exploit.http_client

        self.assertIn("http://", client.base_url)
        self.assertNotIn("https://", client.base_url)

    def test_http_client_with_https_scheme(self):
        """Test HTTP client uses HTTPS scheme when SSL is True"""
        exploit = self.exploit_class()
        exploit.datastore["SSL"] = True

        client = exploit.http_client

        self.assertIn("https://", client.base_url)


class TestHttpClientIntegration(unittest.TestCase):
    """Integration tests for HTTP client usage"""

    @patch("python_framework.helpers.http_client.requests.Session.request")
    def test_complete_http_workflow(self, mock_request):
        """Test complete HTTP workflow with cookies and headers"""
        mock_response = Mock(spec=requests.Response)
        mock_response.status_code = 200
        mock_response.text = "Success"
        mock_response.headers = {"Set-Cookie": "session=abc123"}
        mock_request.return_value = mock_response

        client = HttpClient(base_url="https://example.com")

        # Set custom header
        client.set_header("X-API-Key", "secret")

        # Make authenticated request
        response = client.get("/api/data", headers={"Authorization": "Bearer token"})

        self.assertEqual(response.status_code, 200)

        # Verify custom headers were sent
        _, kwargs = mock_request.call_args
        self.assertIn("X-API-Key", kwargs["headers"])
        self.assertIn("Authorization", kwargs["headers"])

        # Clean up
        client.close()


if __name__ == "__main__":
    unittest.main()
