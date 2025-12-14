"""
HTTP Client helper for exploit development

Provides a comprehensive HTTP client with features commonly needed for exploits:
- SSL/TLS support
- Custom headers and user agents
- Cookie handling
- Proxy support
- Request/response logging
- Timeout handling
"""

import requests
import urllib3
from typing import Dict, Optional, Any, Union, Tuple
from urllib.parse import urljoin, urlparse
import logging
import time


# Disable SSL warnings for exploit development
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)


class HttpClient:
    """
    HTTP client tailored for exploit development needs.
    
    Features:
    - Automatic SSL verification bypass
    - Custom timeout handling
    - Request/response logging
    - Cookie persistence
    - Proxy support
    - Custom headers
    """
    
    def __init__(self, 
                 base_url: str = "",
                 ssl: bool = False,
                 verify_ssl: bool = False,
                 timeout: int = 10,
                 user_agent: str = "Mozilla/5.0 (compatible; Metasploit)",
                 proxy: Optional[Dict[str, str]] = None,
                 verbose: bool = False):
        """
        Initialize HTTP client
        
        Args:
            base_url: Base URL for requests
            ssl: Use HTTPS
            verify_ssl: Verify SSL certificates
            timeout: Request timeout in seconds
            user_agent: User-Agent header value
            proxy: Proxy configuration dict
            verbose: Enable verbose logging
        """
        self.base_url = base_url
        self.ssl = ssl
        self.verify_ssl = verify_ssl
        self.timeout = timeout
        self.verbose = verbose
        
        # Create session for cookie persistence
        self.session = requests.Session()
        
        # Set default headers
        self.session.headers.update({
            'User-Agent': user_agent,
            'Accept': '*/*',
            'Accept-Language': 'en-US,en;q=0.9',
            'Accept-Encoding': 'gzip, deflate',
            'Connection': 'keep-alive'
        })
        
        # Configure SSL
        self.session.verify = verify_ssl
        
        # Configure proxy
        if proxy:
            self.session.proxies.update(proxy)
        
        # Setup logging
        self.logger = logging.getLogger(f"{__name__}.HttpClient")
    
    def _build_url(self, path: str) -> str:
        """Build full URL from base URL and path"""
        if self.base_url:
            return urljoin(self.base_url, path)
        return path
    
    def _log_request(self, method: str, url: str, **kwargs) -> None:
        """Log request details if verbose mode is enabled"""
        if self.verbose:
            self.logger.info(f"HTTP {method.upper()} {url}")
            if 'headers' in kwargs:
                for key, value in kwargs['headers'].items():
                    self.logger.debug(f"  {key}: {value}")
            if 'data' in kwargs and kwargs['data']:
                self.logger.debug(f"  Body: {kwargs['data'][:200]}...")
    
    def _log_response(self, response: requests.Response) -> None:
        """Log response details if verbose mode is enabled"""
        if self.verbose:
            self.logger.info(f"HTTP {response.status_code} {response.reason}")
            for key, value in response.headers.items():
                self.logger.debug(f"  {key}: {value}")
            if response.text:
                self.logger.debug(f"  Body: {response.text[:200]}...")
    
    def request(self, 
                method: str, 
                path: str, 
                headers: Optional[Dict[str, str]] = None,
                data: Optional[Union[str, bytes, Dict]] = None,
                params: Optional[Dict[str, str]] = None,
                json_data: Optional[Dict] = None,
                files: Optional[Dict] = None,
                allow_redirects: bool = True,
                timeout: Optional[int] = None) -> requests.Response:
        """
        Make HTTP request
        
        Args:
            method: HTTP method (GET, POST, etc.)
            path: URL path or full URL
            headers: Additional headers
            data: Request body data
            params: URL parameters
            json_data: JSON data to send
            files: Files to upload
            allow_redirects: Follow redirects
            timeout: Request timeout (overrides default)
            
        Returns:
            requests.Response object
        """
        url = self._build_url(path)
        
        # Merge headers
        req_headers = self.session.headers.copy()
        if headers:
            req_headers.update(headers)
        
        # Use provided timeout or default
        req_timeout = timeout or self.timeout
        
        # Prepare request arguments
        kwargs = {
            'headers': req_headers,
            'timeout': req_timeout,
            'allow_redirects': allow_redirects
        }
        
        if data is not None:
            kwargs['data'] = data
        if params:
            kwargs['params'] = params
        if json_data:
            kwargs['json'] = json_data
        if files:
            kwargs['files'] = files
        
        # Log request
        self._log_request(method, url, **kwargs)
        
        try:
            # Make request
            response = self.session.request(method, url, **kwargs)
            
            # Log response
            self._log_response(response)
            
            return response
            
        except requests.exceptions.RequestException as e:
            self.logger.error(f"HTTP request failed: {e}")
            raise
    
    def get(self, path: str, **kwargs) -> requests.Response:
        """Make GET request"""
        return self.request('GET', path, **kwargs)
    
    def post(self, path: str, **kwargs) -> requests.Response:
        """Make POST request"""
        return self.request('POST', path, **kwargs)
    
    def put(self, path: str, **kwargs) -> requests.Response:
        """Make PUT request"""
        return self.request('PUT', path, **kwargs)
    
    def delete(self, path: str, **kwargs) -> requests.Response:
        """Make DELETE request"""
        return self.request('DELETE', path, **kwargs)
    
    def head(self, path: str, **kwargs) -> requests.Response:
        """Make HEAD request"""
        return self.request('HEAD', path, **kwargs)
    
    def options(self, path: str, **kwargs) -> requests.Response:
        """Make OPTIONS request"""
        return self.request('OPTIONS', path, **kwargs)
    
    def set_cookie(self, name: str, value: str, domain: Optional[str] = None) -> None:
        """Set a cookie"""
        self.session.cookies.set(name, value, domain=domain)
    
    def get_cookie(self, name: str) -> Optional[str]:
        """Get a cookie value"""
        return self.session.cookies.get(name)
    
    def clear_cookies(self) -> None:
        """Clear all cookies"""
        self.session.cookies.clear()
    
    def set_header(self, name: str, value: str) -> None:
        """Set a default header"""
        self.session.headers[name] = value
    
    def remove_header(self, name: str) -> None:
        """Remove a default header"""
        if name in self.session.headers:
            del self.session.headers[name]
    
    def close(self) -> None:
        """Close the session"""
        self.session.close()


class HttpExploitMixin:
    """
    Mixin class to add HTTP client functionality to exploits.
    
    This mixin provides convenient HTTP methods that automatically
    use the exploit's configuration options.
    """
    
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self._http_client: Optional[HttpClient] = None
    
    @property
    def http_client(self) -> HttpClient:
        """Get or create HTTP client instance"""
        if self._http_client is None:
            # Build base URL from exploit options
            scheme = "https" if self.get_option('SSL', False) else "http"
            host = self.get_option('RHOSTS', 'localhost')
            port = self.get_option('RPORT', 80)
            
            # Handle multiple hosts - use first one for base URL
            if ',' in host:
                host = host.split(',')[0].strip()
            
            base_url = f"{scheme}://{host}:{port}"
            
            self._http_client = HttpClient(
                base_url=base_url,
                ssl=self.get_option('SSL', False),
                verify_ssl=False,  # Typically disabled for exploits
                timeout=self.get_option('ConnectTimeout', 10),
                verbose=self.get_option('VERBOSE', False)
            )
        
        return self._http_client
    
    def http_get(self, path: str, **kwargs) -> requests.Response:
        """Make HTTP GET request using exploit configuration"""
        return self.http_client.get(path, **kwargs)
    
    def http_post(self, path: str, **kwargs) -> requests.Response:
        """Make HTTP POST request using exploit configuration"""
        return self.http_client.post(path, **kwargs)
    
    def http_put(self, path: str, **kwargs) -> requests.Response:
        """Make HTTP PUT request using exploit configuration"""
        return self.http_client.put(path, **kwargs)
    
    def http_delete(self, path: str, **kwargs) -> requests.Response:
        """Make HTTP DELETE request using exploit configuration"""
        return self.http_client.delete(path, **kwargs)
    
    def cleanup_http(self) -> None:
        """Clean up HTTP client resources"""
        if self._http_client:
            self._http_client.close()
            self._http_client = None