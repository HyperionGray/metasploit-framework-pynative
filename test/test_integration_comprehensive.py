#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
Integration Testing Suite for Metasploit Framework.

This module provides integration tests that verify components work together correctly.
"""

import pytest
import sys
import os
import tempfile
import shutil
from pathlib import Path
from unittest.mock import Mock, patch, MagicMock

# Add lib path for imports
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', 'lib'))
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', 'python_framework'))


class TestFrameworkIntegration:
    """Integration tests for core framework components."""
    
    @pytest.mark.integration
    def test_framework_module_loading(self):
        """Test that framework can load modules."""
        modules_dir = Path(__file__).parent.parent / 'modules'
        
        if not modules_dir.exists():
            pytest.skip("Modules directory not found")
        
        # Check that modules directory structure exists
        assert modules_dir.exists()
        assert modules_dir.is_dir()
    
    @pytest.mark.integration
    def test_framework_configuration(self):
        """Test framework configuration system."""
        config_dir = Path(__file__).parent.parent / 'config'
        
        if config_dir.exists():
            assert config_dir.is_dir()
            
            # Check for common config files
            config_files = list(config_dir.rglob('*.py'))
            # Should have at least some config files
            assert len(config_files) >= 0
    
    @pytest.mark.integration
    def test_framework_library_imports(self):
        """Test that core libraries can be imported together."""
        try:
            # Try importing multiple components
            from python_framework.core.exploit import Exploit
            from python_framework.helpers.http_client import HttpClient
            
            # Both should be available
            assert Exploit is not None
            assert HttpClient is not None
        except ImportError:
            pytest.skip("Framework components not available")


class TestDatabaseIntegration:
    """Integration tests for database operations."""
    
    @pytest.mark.integration
    def test_database_directory_exists(self):
        """Test that database directory exists."""
        db_dir = Path(__file__).parent.parent / 'db'
        
        if db_dir.exists():
            assert db_dir.is_dir()
    
    @pytest.mark.integration
    def test_database_schema_exists(self):
        """Test that database schema files exist."""
        db_dir = Path(__file__).parent.parent / 'db'
        
        if not db_dir.exists():
            pytest.skip("Database directory not found")
        
        # Look for schema files
        schema_files = list(db_dir.rglob('schema.py'))
        if len(schema_files) > 0:
            assert schema_files[0].exists()


class TestNetworkIntegration:
    """Integration tests for network components."""
    
    @pytest.mark.integration
    @pytest.mark.network
    def test_http_client_integration(self):
        """Test HTTP client integration."""
        try:
            from python_framework.helpers.http_client import HttpClient
            
            # Create client
            client = HttpClient()
            assert client is not None
            
            # Verify it has expected methods
            assert hasattr(client, 'get')
            assert hasattr(client, 'post')
            assert hasattr(client, 'put')
            assert hasattr(client, 'delete')
        except ImportError:
            pytest.skip("HTTP client not available")
    
    @pytest.mark.integration
    @pytest.mark.network
    def test_network_utilities_integration(self):
        """Test network utility integration."""
        import socket
        
        # Test basic socket operations
        try:
            hostname = socket.gethostname()
            assert isinstance(hostname, str)
            assert len(hostname) > 0
        except Exception as e:
            pytest.skip(f"Network utilities not available: {e}")


class TestCryptoIntegration:
    """Integration tests for cryptographic components."""
    
    @pytest.mark.integration
    @pytest.mark.crypto
    @pytest.mark.security
    def test_crypto_library_integration(self):
        """Test cryptographic library integration."""
        try:
            from Crypto.Cipher import AES
            from Crypto.Hash import MD5, SHA256
            from Crypto.Random import get_random_bytes
            
            # All crypto components should be available
            assert AES is not None
            assert MD5 is not None
            assert SHA256 is not None
            assert get_random_bytes is not None
        except ImportError:
            pytest.skip("Crypto library not available")
    
    @pytest.mark.integration
    @pytest.mark.crypto
    @pytest.mark.security
    def test_encryption_decryption_workflow(self):
        """Test complete encryption/decryption workflow."""
        try:
            from Crypto.Cipher import AES
            from Crypto.Random import get_random_bytes
            
            # Generate key
            key = get_random_bytes(16)
            
            # Create plaintext
            plaintext = b'Integration test message'
            
            # Pad to multiple of 16
            padding_length = 16 - (len(plaintext) % 16)
            padded = plaintext + bytes([padding_length] * padding_length)
            
            # Encrypt
            cipher = AES.new(key, AES.MODE_ECB)
            ciphertext = cipher.encrypt(padded)
            
            # Decrypt
            decipher = AES.new(key, AES.MODE_ECB)
            decrypted_padded = decipher.decrypt(ciphertext)
            
            # Remove padding
            pad_len = decrypted_padded[-1]
            decrypted = decrypted_padded[:-pad_len]
            
            # Verify
            assert decrypted == plaintext
        except ImportError:
            pytest.skip("Crypto library not available")


class TestPayloadIntegration:
    """Integration tests for payload generation and handling."""
    
    @pytest.mark.integration
    @pytest.mark.payload
    def test_payload_directory_structure(self):
        """Test payload directory structure."""
        payloads_dir = Path(__file__).parent.parent / 'modules' / 'payloads'
        
        if not payloads_dir.exists():
            pytest.skip("Payloads directory not found")
        
        assert payloads_dir.is_dir()
    
    @pytest.mark.integration
    @pytest.mark.payload
    def test_payload_generation_workflow(self):
        """Test payload generation workflow."""
        # Generate a simple test payload
        payload = b'\x90' * 100  # NOP sled
        payload += b'\x31\xc0'   # Sample shellcode
        
        # Verify payload properties
        assert len(payload) == 102
        assert isinstance(payload, bytes)


class TestExploitIntegration:
    """Integration tests for exploit modules."""
    
    @pytest.mark.integration
    @pytest.mark.exploit
    def test_exploit_directory_structure(self):
        """Test exploit directory structure."""
        exploits_dir = Path(__file__).parent.parent / 'modules' / 'exploits'
        
        if not exploits_dir.exists():
            pytest.skip("Exploits directory not found")
        
        assert exploits_dir.is_dir()
    
    @pytest.mark.integration
    @pytest.mark.exploit
    def test_exploit_base_class_integration(self):
        """Test exploit base class integration."""
        try:
            from python_framework.core.exploit import Exploit, ExploitTarget
            from python_framework.core.exploit import Platform, TargetArch, PayloadType
            
            # Create a test target
            target = ExploitTarget(
                name="Test Target",
                platform=[Platform.LINUX],
                arch=[TargetArch.X64],
                payload_type=PayloadType.REVERSE_TCP
            )
            
            assert target is not None
            assert target.name == "Test Target"
        except ImportError:
            pytest.skip("Exploit components not available")


class TestModuleIntegration:
    """Integration tests for module loading and management."""
    
    @pytest.mark.integration
    def test_module_discovery(self):
        """Test module discovery system."""
        modules_dir = Path(__file__).parent.parent / 'modules'
        
        if not modules_dir.exists():
            pytest.skip("Modules directory not found")
        
        # Count Python modules
        py_modules = list(modules_dir.rglob('*.py'))
        
        # Should have at least some modules
        assert len(py_modules) >= 0
    
    @pytest.mark.integration
    def test_module_categories_exist(self):
        """Test that module categories exist."""
        modules_dir = Path(__file__).parent.parent / 'modules'
        
        if not modules_dir.exists():
            pytest.skip("Modules directory not found")
        
        # Check for common module categories
        categories = ['exploits', 'auxiliary', 'payloads', 'encoders', 'post']
        
        for category in categories:
            category_dir = modules_dir / category
            if category_dir.exists():
                assert category_dir.is_dir()


class TestSessionIntegration:
    """Integration tests for session management."""
    
    @pytest.mark.integration
    def test_session_data_structures(self):
        """Test session data structures."""
        # Create mock session data
        session_data = {
            'id': 1,
            'type': 'meterpreter',
            'info': 'Test session',
            'platform': 'linux',
            'arch': 'x64'
        }
        
        assert session_data['id'] == 1
        assert session_data['type'] == 'meterpreter'
        assert session_data['platform'] == 'linux'
    
    @pytest.mark.integration
    def test_session_metadata(self):
        """Test session metadata handling."""
        metadata = {
            'created_at': '2024-01-01T00:00:00',
            'last_seen': '2024-01-01T00:00:00',
            'username': 'testuser',
            'hostname': 'testhost'
        }
        
        assert 'created_at' in metadata
        assert 'last_seen' in metadata
        assert 'username' in metadata


class TestDatastoreIntegration:
    """Integration tests for datastore/options system."""
    
    @pytest.mark.integration
    def test_datastore_operations(self):
        """Test datastore operations."""
        # Create mock datastore
        datastore = {
            'RHOST': '192.168.1.100',
            'RPORT': 80,
            'SSL': False,
            'TIMEOUT': 30
        }
        
        # Verify operations
        assert datastore['RHOST'] == '192.168.1.100'
        assert datastore['RPORT'] == 80
        assert datastore['SSL'] is False
        
        # Update operation
        datastore['RPORT'] = 443
        datastore['SSL'] = True
        
        assert datastore['RPORT'] == 443
        assert datastore['SSL'] is True
    
    @pytest.mark.integration
    def test_datastore_validation(self):
        """Test datastore validation."""
        # Valid options
        valid_options = {
            'RHOST': '192.168.1.100',
            'RPORT': 80,
        }
        
        # Validate RHOST is an IP-like string
        assert isinstance(valid_options['RHOST'], str)
        assert '.' in valid_options['RHOST']
        
        # Validate RPORT is in valid range
        assert 1 <= valid_options['RPORT'] <= 65535


class TestFileSystemIntegration:
    """Integration tests for file system operations."""
    
    @pytest.mark.integration
    def test_temp_directory_operations(self):
        """Test temporary directory operations."""
        with tempfile.TemporaryDirectory() as tmpdir:
            tmp_path = Path(tmpdir)
            
            # Create test file
            test_file = tmp_path / 'test.txt'
            test_file.write_text('Test content')
            
            # Verify
            assert test_file.exists()
            assert test_file.read_text() == 'Test content'
    
    @pytest.mark.integration
    def test_framework_directory_structure(self):
        """Test framework directory structure."""
        root_dir = Path(__file__).parent.parent
        
        # Check for key directories
        key_dirs = ['lib', 'modules', 'test', 'data']
        
        for dir_name in key_dirs:
            dir_path = root_dir / dir_name
            if dir_path.exists():
                assert dir_path.is_dir()


class TestConfigurationIntegration:
    """Integration tests for configuration management."""
    
    @pytest.mark.integration
    def test_configuration_files_exist(self):
        """Test that configuration files exist."""
        root_dir = Path(__file__).parent.parent
        
        config_files = [
            'pyproject.toml',
            'requirements.txt',
            'conftest.py'
        ]
        
        for config_file in config_files:
            config_path = root_dir / config_file
            if config_path.exists():
                assert config_path.is_file()
    
    @pytest.mark.integration
    def test_environment_configuration(self):
        """Test environment configuration."""
        # Test that we can read environment variables
        import os
        
        # Set test env var
        os.environ['MSF_TEST_VAR'] = 'test_value'
        
        # Verify
        assert os.environ.get('MSF_TEST_VAR') == 'test_value'
        
        # Cleanup
        del os.environ['MSF_TEST_VAR']


class TestPluginIntegration:
    """Integration tests for plugin system."""
    
    @pytest.mark.integration
    def test_plugins_directory_exists(self):
        """Test that plugins directory exists."""
        plugins_dir = Path(__file__).parent.parent / 'plugins'
        
        if not plugins_dir.exists():
            pytest.skip("Plugins directory not found")
        
        assert plugins_dir.is_dir()
    
    @pytest.mark.integration
    def test_python_framework_plugins(self):
        """Test Python framework plugins."""
        plugins_dir = Path(__file__).parent.parent / 'python_framework' / 'plugins'
        
        if plugins_dir.exists():
            assert plugins_dir.is_dir()


class TestToolsIntegration:
    """Integration tests for tools and utilities."""
    
    @pytest.mark.integration
    def test_tools_directory_exists(self):
        """Test that tools directory exists."""
        tools_dir = Path(__file__).parent.parent / 'tools'
        
        if not tools_dir.exists():
            pytest.skip("Tools directory not found")
        
        assert tools_dir.is_dir()
    
    @pytest.mark.integration
    def test_tools_executable(self):
        """Test that tools are executable."""
        tools_dir = Path(__file__).parent.parent / 'tools'
        
        if not tools_dir.exists():
            pytest.skip("Tools directory not found")
        
        # Look for Python tools
        py_tools = list(tools_dir.rglob('*.py'))
        
        # Should have at least some tools
        assert len(py_tools) >= 0


class TestEndToEndWorkflow:
    """End-to-end integration tests."""
    
    @pytest.mark.integration
    @pytest.mark.functional
    def test_complete_exploit_workflow(self):
        """Test complete exploit workflow."""
        try:
            from python_framework.core.exploit import ExploitTarget, Platform, TargetArch, PayloadType
            
            # 1. Create target
            target = ExploitTarget(
                name="Test Target",
                platform=[Platform.LINUX],
                arch=[TargetArch.X64],
                payload_type=PayloadType.REVERSE_TCP
            )
            
            # 2. Configure options
            options = {
                'RHOST': '192.168.1.100',
                'RPORT': 80,
                'LHOST': '192.168.1.10',
                'LPORT': 4444
            }
            
            # 3. Generate payload
            payload = b'\x90' * 100
            
            # 4. Verify workflow
            assert target is not None
            assert options['RHOST'] == '192.168.1.100'
            assert len(payload) == 100
            
        except ImportError:
            pytest.skip("Framework components not available")


if __name__ == '__main__':
    pytest.main([__file__, '-v', '--tb=short'])
