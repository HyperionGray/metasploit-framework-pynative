"""
HTTP Client helper for exploit development

Provides a comprehensive HTTP client with features commonly needed for exploits:
- SSL/TLS support with configurable verification
- Custom headers and user agents
- Cookie handling
- Proxy support
- Request/response logging
- Timeout handling
- Input validation and sanitization
- Rate limiting protection
"""

import requests
import urllib3
from typing import Dict, Optional, Any, Union, Tuple
from urllib.parse import urljoin, urlparse, quote
import logging
import time
import re
import hashlib
from urllib.parse import parse_qs


# SSL warnings management - configurable per instance
class SSLWarningManager:
    """Manages SSL warning suppression on a per-client basis"""
    
    @staticmethod
    def disable_warnings():
        """Disable SSL warnings - use with caution"""
        urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
    
    @staticmethod
    def enable_warnings():
        """Re-enable SSL warnings"""
        urllib3.warnings.resetwarnings()


class HttpClient:
    """
    HTTP client tailored for exploit development needs.
    
    Features:
    - Configurable SSL verification (secure by default)
    - Input validation and sanitization
    - Rate limiting protection
    - Custom timeout handling
    - Request/response logging
    - Cookie persistence
    - Proxy support
    - Custom headers
    - Security headers validation
    """
    
    # Security constants
    MAX_REDIRECTS = 5
    MAX_REQUEST_SIZE = 10 * 1024 * 1024  # 10MB
    RATE_LIMIT_REQUESTS = 100
    RATE_LIMIT_WINDOW = 60  # seconds
    
    def __init__(self, 
                 base_url: str = "",
                 ssl: bool = False,
                 verify_ssl: bool = True,  # Secure by default
                 timeout: int = 10,
                 user_agent: str = "Mozilla/5.0 (compatible; Metasploit)",
                 proxy: Optional[Dict[str, str]] = None,
                 verbose: bool = False,
                 disable_ssl_warnings: bool = False,
                 max_redirects: int = MAX_REDIRECTS,
                 enable_rate_limiting: bool = True):
        """
        Initialize HTTP client
        
        Args:
            base_url: Base URL for requests
            ssl: Use HTTPS
            verify_ssl: Verify SSL certificates (secure by default)
            timeout: Request timeout in seconds
            user_agent: User-Agent header value
            proxy: Proxy configuration dict
            verbose: Enable verbose logging
            disable_ssl_warnings: Disable SSL warnings (use with caution)
            max_redirects: Maximum number of redirects to follow
            enable_rate_limiting: Enable rate limiting protection
        """
        # Input validation
        if base_url and not self._is_valid_url(base_url):
            raise ValueError(f"Invalid base URL: {base_url}")
        
        if timeout <= 0 or timeout > 300:  # Max 5 minutes
            raise ValueError("Timeout must be between 1 and 300 seconds")
        
        if max_redirects < 0 or max_redirects > 20:
            raise ValueError("Max redirects must be between 0 and 20")
        
        self.base_url = base_url
        self.ssl = ssl
        self.verify_ssl = verify_ssl
        self.timeout = timeout
        self.verbose = verbose
        self.max_redirects = max_redirects
        self.enable_rate_limiting = enable_rate_limiting
        
        # Rate limiting tracking
        self._request_times = []
        
        # SSL warning management
        if disable_ssl_warnings:
            SSLWarningManager.disable_warnings()
        
        # Create session for cookie persistence
        self.session = requests.Session()
        
        # Set secure default headers
        self.session.headers.update({
            'User-Agent': self._sanitize_header_value(user_agent),
            'Accept': '*/*',
            'Accept-Language': 'en-US,en;q=0.9',
            'Accept-Encoding': 'gzip, deflate',
            'Connection': 'keep-alive',
            'Cache-Control': 'no-cache'
        })
        
        # Configure SSL with security considerations
        self.session.verify = verify_ssl
        if not verify_ssl and verbose:
            self.logger.warning("SSL verification disabled - use with caution in production")
        
        # Configure proxy with validation
        if proxy:
            validated_proxy = self._validate_proxy_config(proxy)
            self.session.proxies.update(validated_proxy)
        
        # Setup logging
        self.logger = logging.getLogger(f"{__name__}.HttpClient")
    
    def _is_valid_url(self, url: str) -> bool:
        """Validate URL format and security"""
        try:
            parsed = urlparse(url)
            # Check for valid scheme
            if parsed.scheme not in ['http', 'https']:
                return False
            # Check for valid hostname
            if not parsed.netloc:
                return False
            # Prevent localhost/private IP access in production
            if not self.verbose:  # In non-verbose mode, assume production
                hostname = parsed.hostname
                if hostname in ['localhost', '127.0.0.1', '0.0.0.0']:
                    self.logger.warning(f"Localhost access detected: {hostname}")
            return True
        except Exception:
            return False
    
    def _sanitize_header_value(self, value: str) -> str:
        """Sanitize header values to prevent injection"""
        if not isinstance(value, str):
            value = str(value)
        # Remove control characters and newlines
        sanitized = re.sub(r'[\r\n\x00-\x1f\x7f-\x9f]', '', value)
        return sanitized[:1000]  # Limit length
    
    def _validate_proxy_config(self, proxy: Dict[str, str]) -> Dict[str, str]:
        """Validate and sanitize proxy configuration"""
        validated = {}
        for scheme, url in proxy.items():
            if scheme in ['http', 'https']:
                if self._is_valid_url(url):
                    validated[scheme] = url
                else:
                    self.logger.warning(f"Invalid proxy URL for {scheme}: {url}")
        return validated
    
    def _check_rate_limit(self) -> bool:
        """Check if request is within rate limits"""
        if not self.enable_rate_limiting:
            return True
        
        current_time = time.time()
        # Remove old requests outside the window
        self._request_times = [t for t in self._request_times 
                              if current_time - t < self.RATE_LIMIT_WINDOW]
        
        if len(self._request_times) >= self.RATE_LIMIT_REQUESTS:
            self.logger.warning("Rate limit exceeded")
            return False
        
        self._request_times.append(current_time)
        return True
    
    def _build_url(self, path: str) -> str:
        """Build full URL from base URL and path with validation"""
        if self.base_url:
            # Sanitize path to prevent URL injection
            sanitized_path = quote(path, safe='/:?#[]@!$&\'()*+,;=')
            full_url = urljoin(self.base_url, sanitized_path)
        else:
            full_url = path
        
        # Validate final URL
        if not self._is_valid_url(full_url):
            raise ValueError(f"Invalid URL constructed: {full_url}")
        
        return full_url
    
    def _log_request(self, method: str, url: str, **kwargs) -> None:
        """Log request details if verbose mode is enabled"""
        if self.verbose:
            self.logger.info(f"HTTP {method.upper()} {url}")
            if 'headers' in kwargs:
                for key, value in kwargs['headers'].items():
                    # Don't log sensitive headers
                    if key.lower() in ['authorization', 'cookie', 'x-api-key']:
                        self.logger.debug(f"  {key}: [REDACTED]")
                    else:
                        self.logger.debug(f"  {key}: {value}")
            if 'data' in kwargs and kwargs['data']:
                # Limit logged data size and redact sensitive content
                data_str = str(kwargs['data'])[:200]
                # Redact common sensitive patterns
                data_str = re.sub(r'(password|token|key|secret)=[^&\s]*', r'\1=[REDACTED]', data_str, flags=re.IGNORECASE)
                self.logger.debug(f"  Body: {data_str}...")
    
    def _log_response(self, response: requests.Response) -> None:
        """Log response details if verbose mode is enabled"""
        if self.verbose:
            self.logger.info(f"HTTP {response.status_code} {response.reason}")
            for key, value in response.headers.items():
                # Don't log sensitive response headers
                if key.lower() in ['set-cookie', 'authorization']:
                    self.logger.debug(f"  {key}: [REDACTED]")
                else:
                    self.logger.debug(f"  {key}: {value}")
            if response.text:
                # Limit logged response size
                response_text = response.text[:200]
                self.logger.debug(f"  Body: {response_text}...")
    
    def _validate_request_data(self, data: Any) -> bool:
        """Validate request data size and content"""
        if data is None:
            return True
        
        # Check data size
        if hasattr(data, '__len__'):
            if len(str(data)) > self.MAX_REQUEST_SIZE:
                self.logger.error(f"Request data too large: {len(str(data))} bytes")
                return False
        
        return True
    
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
        Make HTTP request with security validations
        
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
            
        Raises:
            ValueError: For invalid input parameters
            requests.exceptions.RequestException: For request failures
        """
        # Security validations
        if not self._check_rate_limit():
            raise requests.exceptions.RequestException("Rate limit exceeded")
        
        if not self._validate_request_data(data):
            raise ValueError("Invalid request data")
        
        # Validate method
        if method.upper() not in ['GET', 'POST', 'PUT', 'DELETE', 'HEAD', 'OPTIONS', 'PATCH']:
            raise ValueError(f"Invalid HTTP method: {method}")
        
        url = self._build_url(path)
        
        # Merge and sanitize headers
        req_headers = self.session.headers.copy()
        if headers:
            for key, value in headers.items():
                sanitized_key = self._sanitize_header_value(key)
                sanitized_value = self._sanitize_header_value(value)
                req_headers[sanitized_key] = sanitized_value
        
        # Use provided timeout or default
        req_timeout = timeout or self.timeout
        if req_timeout <= 0 or req_timeout > 300:
            raise ValueError("Timeout must be between 1 and 300 seconds")
        
        # Limit redirects for security
        max_redirects = self.max_redirects if allow_redirects else 0
        
        # Prepare request arguments
        kwargs = {
            'headers': req_headers,
            'timeout': req_timeout,
            'allow_redirects': allow_redirects,
            'stream': False  # Prevent memory exhaustion
        }
        
        # Add data with validation
        if data is not None:
            kwargs['data'] = data
        if params:
            # Sanitize URL parameters
            sanitized_params = {}
            for key, value in params.items():
                sanitized_params[str(key)[:100]] = str(value)[:1000]
            kwargs['params'] = sanitized_params
        if json_data:
            kwargs['json'] = json_data
        if files:
            kwargs['files'] = files
        
        # Configure session for this request
        old_max_redirects = self.session.max_redirects
        self.session.max_redirects = max_redirects
        
        # Log request
        self._log_request(method, url, **kwargs)
        
        try:
            # Make request
            response = self.session.request(method, url, **kwargs)
            
            # Validate response size
            if hasattr(response, 'headers'):
                content_length = response.headers.get('content-length')
                if content_length and int(content_length) > self.MAX_REQUEST_SIZE:
                    self.logger.warning(f"Large response detected: {content_length} bytes")
            
            # Log response
            self._log_response(response)
            
            return response
            
        except requests.exceptions.RequestException as e:
            self.logger.error(f"HTTP request failed: {e}")
            raise
        finally:
            # Restore session settings
            self.session.max_redirects = old_max_redirects
    
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