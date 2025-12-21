#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
Metasploit HTTP Client Library

This module provides HTTP client functionality for Python-based Metasploit modules.
It aims to replicate the functionality of Msf::Exploit::Remote::HttpClient in Ruby.
"""

import requests
import logging
from urllib.parse import urljoin, urlparse
from typing import Optional, Dict, Any, Union


class HTTPClient:
    """
    HTTP Client for Metasploit modules.
    
    Provides a simplified interface for making HTTP requests with common
    security testing features like custom headers, SSL verification control,
    and proxy support.
    """
    
    def __init__(self, rhost: str, rport: int = 80, ssl: bool = False,
                 vhost: Optional[str] = None, timeout: int = 30,
                 proxies: Optional[Dict[str, str]] = None):
        """
        Initialize HTTP client.
        
        Args:
            rhost: Remote host address
            rport: Remote port number
            ssl: Use HTTPS if True
            vhost: Virtual host name for Host header
            timeout: Request timeout in seconds
            proxies: Proxy configuration dict
        """
        self.rhost = rhost
        self.rport = rport
        self.ssl = ssl
        self.vhost = vhost or rhost
        self.timeout = timeout
        self.proxies = proxies or {}
        
        # Build base URL
        scheme = 'https' if ssl else 'http'
        self.base_url = f"{scheme}://{rhost}:{rport}"
        
        # Default headers
        self.default_headers = {
            'Host': f"{self.vhost}:{rport}",
            'User-Agent': 'Mozilla/5.0 (compatible; Metasploit)',
            'Accept': '*/*',
            'Accept-Language': 'en-US,en;q=0.5',
            'Accept-Encoding': 'gzip, deflate'
        }
        
        # Create session for connection pooling
        self.session = requests.Session()
        self.session.headers.update(self.default_headers)
        
        # Disable SSL verification by default (security testing)
        self.session.verify = False
        
        # Suppress SSL warnings
        import urllib3
        urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
    
    def normalize_uri(self, *paths: str) -> str:
        """
        Normalize URI path components.
        
        Args:
            *paths: Path components to join
            
        Returns:
            Normalized URI path
        """
        # Join paths and ensure single leading slash
        path = '/'.join(str(p).strip('/') for p in paths if p)
        return '/' + path if path else '/'
    
    def send_request_cgi(self, uri: str = '/', method: str = 'GET',
                        data: Optional[Union[str, bytes, Dict]] = None,
                        headers: Optional[Dict[str, str]] = None,
                        params: Optional[Dict[str, str]] = None,
                        cookies: Optional[Dict[str, str]] = None,
                        **kwargs) -> Optional[requests.Response]:
        """
        Send HTTP request (compatible with Ruby's send_request_cgi).
        
        Args:
            uri: Request URI path
            method: HTTP method (GET, POST, etc.)
            data: Request body data
            headers: Additional headers
            params: Query parameters
            cookies: Cookies to send
            **kwargs: Additional requests parameters
            
        Returns:
            Response object or None on error
        """
        try:
            url = urljoin(self.base_url, uri)
            
            # Merge headers
            req_headers = self.default_headers.copy()
            if headers:
                req_headers.update(headers)
            
            # Make request
            response = self.session.request(
                method=method.upper(),
                url=url,
                data=data,
                headers=req_headers,
                params=params,
                cookies=cookies,
                timeout=self.timeout,
                proxies=self.proxies,
                allow_redirects=True,
                **kwargs
            )
            
            logging.debug(f"HTTP {method} {url} -> {response.status_code}")
            return response
            
        except requests.exceptions.RequestException as e:
            logging.error(f"HTTP request failed: {e}")
            return None
    
    def get(self, uri: str = '/', headers: Optional[Dict[str, str]] = None,
            params: Optional[Dict[str, str]] = None, **kwargs) -> Optional[requests.Response]:
        """
        Send HTTP GET request.
        
        Args:
            uri: Request URI path
            headers: Additional headers
            params: Query parameters
            **kwargs: Additional parameters
            
        Returns:
            Response object or None on error
        """
        return self.send_request_cgi(uri=uri, method='GET', headers=headers,
                                     params=params, **kwargs)
    
    def post(self, uri: str = '/', data: Optional[Union[str, bytes, Dict]] = None,
             headers: Optional[Dict[str, str]] = None,
             params: Optional[Dict[str, str]] = None, **kwargs) -> Optional[requests.Response]:
        """
        Send HTTP POST request.
        
        Args:
            uri: Request URI path
            data: POST data
            headers: Additional headers
            params: Query parameters
            **kwargs: Additional parameters
            
        Returns:
            Response object or None on error
        """
        return self.send_request_cgi(uri=uri, method='POST', data=data,
                                     headers=headers, params=params, **kwargs)
    
    def put(self, uri: str = '/', data: Optional[Union[str, bytes, Dict]] = None,
            headers: Optional[Dict[str, str]] = None, **kwargs) -> Optional[requests.Response]:
        """
        Send HTTP PUT request.
        
        Args:
            uri: Request URI path
            data: PUT data
            headers: Additional headers
            **kwargs: Additional parameters
            
        Returns:
            Response object or None on error
        """
        return self.send_request_cgi(uri=uri, method='PUT', data=data,
                                     headers=headers, **kwargs)
    
    def delete(self, uri: str = '/', headers: Optional[Dict[str, str]] = None,
               **kwargs) -> Optional[requests.Response]:
        """
        Send HTTP DELETE request.
        
        Args:
            uri: Request URI path
            headers: Additional headers
            **kwargs: Additional parameters
            
        Returns:
            Response object or None on error
        """
        return self.send_request_cgi(uri=uri, method='DELETE',
                                     headers=headers, **kwargs)
    
    def close(self):
        """Close the HTTP session and cleanup resources."""
        if self.session:
            self.session.close()
    
    def __enter__(self):
        """Context manager entry."""
        return self
    
    def __exit__(self, exc_type, exc_val, exc_tb):
        """Context manager exit."""
        self.close()


class CheckCode:
    """Check code constants for vulnerability detection."""
    UNKNOWN = 'unknown'
    SAFE = 'safe'
    DETECTED = 'detected'
    APPEARS = 'appears'
    VULNERABLE = 'vulnerable'
    UNSUPPORTED = 'unsupported'


def create_http_client(args: Dict[str, Any]) -> HTTPClient:
    """
    Create HTTP client from module arguments.
    
    Args:
        args: Module arguments dictionary
        
    Returns:
        Configured HTTPClient instance
    """
    rhost = args.get('rhost') or args.get('RHOST')
    rport = args.get('rport') or args.get('RPORT', 80)
    ssl = args.get('ssl') or args.get('SSL', False)
    vhost = args.get('vhost') or args.get('VHOST')
    
    return HTTPClient(rhost=rhost, rport=rport, ssl=ssl, vhost=vhost)


# For backward compatibility
def send_request_cgi(rhost: str, rport: int, uri: str = '/', method: str = 'GET',
                    **kwargs) -> Optional[requests.Response]:
    """
    Standalone function to send HTTP request.
    
    This is a compatibility function for quick requests without creating a client.
    
    Args:
        rhost: Remote host
        rport: Remote port
        uri: Request URI
        method: HTTP method
        **kwargs: Additional parameters
        
    Returns:
        Response object or None on error
    """
    with HTTPClient(rhost, rport) as client:
        return client.send_request_cgi(uri=uri, method=method, **kwargs)
