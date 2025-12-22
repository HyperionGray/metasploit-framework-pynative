#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
Global pytest configuration and fixtures for Metasploit Framework testing.

This module provides shared fixtures, test utilities, and configuration
for comprehensive testing of the transpiled Python Metasploit framework.
"""

import os
import sys
import tempfile
import shutil
import socket
import threading
import time
from pathlib import Path
from typing import Dict, Any, Optional, Generator, List
from unittest.mock import Mock, MagicMock, patch

import pytest
import requests
import responses
from faker import Faker
from freezegun import freeze_time
import factory

# Add lib path for imports
sys.path.insert(0, os.path.join(os.path.dirname(__file__), 'lib'))

# Test configuration
TEST_DATA_DIR = Path(__file__).parent / "test" / "fixtures"
TEMP_DIR = Path(tempfile.gettempdir()) / "msf_tests"

# Ensure test directories exist
TEST_DATA_DIR.mkdir(parents=True, exist_ok=True)
TEMP_DIR.mkdir(parents=True, exist_ok=True)


@pytest.fixture(scope="session")
def test_data_dir():
    """Provide path to test data directory."""
    return TEST_DATA_DIR


@pytest.fixture(scope="session")
def temp_dir():
    """Provide temporary directory for test files."""
    return TEMP_DIR


@pytest.fixture
def fake():
    """Provide Faker instance for generating test data."""
    return Faker()


@pytest.fixture
def mock_target():
    """Mock target host configuration."""
    return {
        'rhost': '192.168.1.100',
        'rport': 80,
        'ssl': False,
        'vhost': None,
        'timeout': 30
    }


@pytest.fixture
def mock_http_responses():
    """Mock HTTP responses for testing."""
    with responses.RequestsMock() as rsps:
        # Default responses
        rsps.add(responses.GET, 'http://192.168.1.100:80/', 
                json={'status': 'ok'}, status=200)
        rsps.add(responses.POST, 'http://192.168.1.100:80/login',
                json={'token': 'fake_token'}, status=200)
        rsps.add(responses.GET, 'http://192.168.1.100:80/admin',
                status=403)
        yield rsps


@pytest.fixture
def sample_payloads():
    """Sample payloads for testing."""
    return {
        'linux_x86': b'\x31\xc0\x50\x68\x2f\x2f\x73\x68\x68\x2f\x62\x69\x6e\x89\xe3\x50\x53\x89\xe1\xb0\x0b\xcd\x80',
        'windows_x86': b'\xfc\x48\x83\xe4\xf0\xe8\xc0\x00\x00\x00\x41\x51\x41\x50\x52\x51\x56\x48\x31\xd2',
        'encoded_payload': b'\x90\x90\x90\x90\x31\xc0\x50\x68\x2f\x2f\x73\x68',
        'web_shell': b'<?php system($_GET["cmd"]); ?>'
    }


@pytest.fixture
def sample_exploits():
    """Sample exploit configurations."""
    return {
        'buffer_overflow': {
            'target': 'linux/x86',
            'payload': 'linux/x86/shell_reverse_tcp',
            'buffer_size': 1024,
            'offset': 268,
            'bad_chars': b'\x00\x0a\x0d'
        },
        'web_rce': {
            'target': 'multi/http',
            'payload': 'cmd/unix/reverse',
            'uri': '/vulnerable.php',
            'parameter': 'cmd',
            'method': 'POST'
        },
        'sql_injection': {
            'target': 'multi/http',
            'payload': 'php/meterpreter/reverse_tcp',
            'uri': '/login.php',
            'parameter': 'username',
            'injection_type': 'union'
        }
    }


class MockHTTPServer:
    """Mock HTTP server for testing."""
    
    def __init__(self, host='127.0.0.1', port=0):
        self.host = host
        self.port = port
        self.server = None
        self.thread = None
        
    def start(self):
        """Start the mock server."""
        import http.server
        import socketserver
        
        class Handler(http.server.SimpleHTTPRequestHandler):
            def do_GET(self):
                self.send_response(200)
                self.send_header('Content-type', 'text/html')
                self.end_headers()
                self.wfile.write(b'Mock server response')
                
            def do_POST(self):
                content_length = int(self.headers.get('Content-Length', 0))
                post_data = self.rfile.read(content_length)
                self.send_response(200)
                self.send_header('Content-type', 'application/json')
                self.end_headers()
                self.wfile.write(b'{"status": "received"}')
        
        self.server = socketserver.TCPServer((self.host, self.port), Handler)
        if self.port == 0:
            self.port = self.server.server_address[1]
            
        self.thread = threading.Thread(target=self.server.serve_forever)
        self.thread.daemon = True
        self.thread.start()
        time.sleep(0.1)  # Give server time to start
        
    def stop(self):
        """Stop the mock server."""
        if self.server:
            self.server.shutdown()
            self.server.server_close()
        if self.thread:
            self.thread.join(timeout=1)


@pytest.fixture
def mock_http_server():
    """Provide mock HTTP server for testing."""
    server = MockHTTPServer()
    server.start()
    yield server
    server.stop()


@pytest.fixture
def mock_file_system():
    """Mock file system operations."""
    with patch('builtins.open'), \
         patch('os.path.exists'), \
         patch('os.makedirs'), \
         patch('shutil.copy2'):
        yield


@pytest.fixture
def mock_network():
    """Mock network operations."""
    with patch('socket.socket'), \
         patch('socket.gethostbyname'), \
         patch('socket.getaddrinfo'):
        yield


@pytest.fixture
def mock_subprocess():
    """Mock subprocess operations."""
    with patch('subprocess.run'), \
         patch('subprocess.Popen'), \
         patch('subprocess.check_output'):
        yield


@pytest.fixture
def clean_environment():
    """Clean environment variables for testing."""
    original_env = os.environ.copy()
    # Clear MSF-related environment variables
    for key in list(os.environ.keys()):
        if key.startswith(('MSF_', 'METASPLOIT_')):
            del os.environ[key]
    yield
    # Restore original environment
    os.environ.clear()
    os.environ.update(original_env)


@pytest.fixture
def test_module_metadata():
    """Sample module metadata for testing."""
    return {
        'name': 'Test Exploit Module',
        'description': 'Test exploit for unit testing',
        'author': ['Test Author'],
        'license': 'MSF_LICENSE',
        'references': [
            {'type': 'CVE', 'ref': '2023-1234'},
            {'type': 'URL', 'ref': 'https://example.com/vuln'}
        ],
        'platform': ['linux', 'windows'],
        'targets': [
            {'name': 'Linux x86', 'arch': 'x86'},
            {'name': 'Windows x86', 'arch': 'x86'}
        ],
        'payload': {
            'space': 1000,
            'bad_chars': '\x00\x0a\x0d'
        },
        'options': {
            'RHOST': {
                'type': 'address',
                'description': 'Target host',
                'required': True
            },
            'RPORT': {
                'type': 'port',
                'description': 'Target port',
                'required': True,
                'default': 80
            }
        }
    }


# Factory classes for generating test data
class TargetFactory(factory.Factory):
    """Factory for generating target configurations."""
    
    class Meta:
        model = dict
    
    rhost = factory.Faker('ipv4')
    rport = factory.Faker('port_number')
    ssl = factory.Faker('boolean')
    timeout = 30


class PayloadFactory(factory.Factory):
    """Factory for generating payload configurations."""
    
    class Meta:
        model = dict
    
    name = factory.Faker('word')
    arch = factory.Faker('random_element', elements=['x86', 'x64', 'arm'])
    platform = factory.Faker('random_element', elements=['linux', 'windows', 'osx'])
    size = factory.Faker('random_int', min=100, max=2000)


class ExploitFactory(factory.Factory):
    """Factory for generating exploit configurations."""
    
    class Meta:
        model = dict
    
    name = factory.Faker('sentence', nb_words=3)
    type = factory.Faker('random_element', elements=['remote', 'local', 'webapp'])
    rank = factory.Faker('random_element', elements=['excellent', 'great', 'good', 'normal'])
    reliability = factory.Faker('random_element', elements=['repeatable', 'unreliable'])


# Performance testing utilities
@pytest.fixture
def benchmark_config():
    """Configuration for performance benchmarks."""
    return {
        'min_rounds': 5,
        'max_time': 10.0,
        'warmup': True,
        'warmup_iterations': 2
    }


# Security testing utilities
@pytest.fixture
def security_test_vectors():
    """Security test vectors for cryptographic testing."""
    return {
        'md5_vectors': [
            {'input': b'', 'expected': 'd41d8cd98f00b204e9800998ecf8427e'},
            {'input': b'a', 'expected': '0cc175b9c0f1b6a831c399e269772661'},
            {'input': b'abc', 'expected': '900150983cd24fb0d6963f7d28e17f72'}
        ],
        'sha256_vectors': [
            {'input': b'', 'expected': 'e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855'},
            {'input': b'abc', 'expected': 'ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad'}
        ],
        'aes_vectors': [
            {
                'key': bytes.fromhex('2b7e151628aed2a6abf7158809cf4f3c'),
                'plaintext': bytes.fromhex('6bc1bee22e409f96e93d7e117393172a'),
                'ciphertext': bytes.fromhex('3ad77bb40d7a3660a89ecaf32466ef97')
            }
        ]
    }


# Module loading utilities
@pytest.fixture
def module_loader():
    """Utility for loading and testing modules."""
    class ModuleLoader:
        def __init__(self):
            self.loaded_modules = {}
            
        def load_module(self, module_path: str) -> Any:
            """Load a module for testing."""
            # Implementation would load actual modules
            return Mock()
            
        def validate_module(self, module: Any) -> bool:
            """Validate module structure."""
            # Implementation would validate module metadata
            return True
            
        def get_module_options(self, module: Any) -> Dict[str, Any]:
            """Get module options."""
            return {}
    
    return ModuleLoader()


# Cleanup fixtures
@pytest.fixture(autouse=True)
def cleanup_temp_files():
    """Automatically cleanup temporary files after each test."""
    yield
    # Cleanup any temporary files created during testing
    if TEMP_DIR.exists():
        for item in TEMP_DIR.iterdir():
            if item.is_file():
                item.unlink()
            elif item.is_dir():
                shutil.rmtree(item)


# Test markers and utilities
def pytest_configure(config):
    """Configure pytest with custom markers."""
    config.addinivalue_line(
        "markers", "requires_network: mark test as requiring network access"
    )
    config.addinivalue_line(
        "markers", "requires_root: mark test as requiring root privileges"
    )
    config.addinivalue_line(
        "markers", "slow_test: mark test as slow running"
    )


def pytest_collection_modifyitems(config, items):
    """Modify test collection to add markers based on test names."""
    for item in items:
        # Add network marker for tests with 'network' in name
        if 'network' in item.name.lower():
            item.add_marker(pytest.mark.network)
        
        # Add slow marker for tests with 'slow' in name
        if 'slow' in item.name.lower():
            item.add_marker(pytest.mark.slow)
        
        # Add security marker for tests with 'security' or 'crypto' in name
        if any(word in item.name.lower() for word in ['security', 'crypto', 'encrypt']):
            item.add_marker(pytest.mark.security)


# Skip conditions
skip_if_no_network = pytest.mark.skipif(
    not hasattr(socket, 'create_connection'),
    reason="Network access not available"
)

skip_if_not_root = pytest.mark.skipif(
    os.geteuid() != 0 if hasattr(os, 'geteuid') else False,
    reason="Requires root privileges"
)

skip_if_no_external_tools = pytest.mark.skipif(
    not shutil.which('radare2'),
    reason="External tools not available"
)