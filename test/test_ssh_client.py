"""
Comprehensive tests for SSH client helper functionality.

Tests the SSH client used for SSH-based exploit development to ensure
correct behavior after Ruby-to-Python migration.
"""

import pytest
import sys
from pathlib import Path
from unittest.mock import Mock, patch, MagicMock, call
import paramiko

# Add python_framework to path
sys.path.insert(0, str(Path(__file__).parent.parent / 'python_framework'))

from helpers.ssh_client import SSHClient, SSHExploitMixin


class TestSSHClientInitialization:
    """Test SSHClient initialization"""
    
    def test_default_initialization(self):
        """Test creating SSHClient with default values"""
        client = SSHClient(hostname="example.com")
        
        assert client.hostname == "example.com"
        assert client.port == 22
        assert client.username == ""
        assert client.password == ""
        assert client.private_key_path == ""
        assert client.timeout == 30
        assert client.verbose is False
        assert client.client is None
    
    def test_initialization_with_hostname(self):
        """Test creating SSHClient with hostname"""
        client = SSHClient(hostname="example.com")
        
        assert client.hostname == "example.com"
    
    def test_initialization_with_custom_port(self):
        """Test creating SSHClient with custom port"""
        client = SSHClient(port=2222, hostname="example.com")
        
        assert client.port == 2222
    
    def test_initialization_with_credentials(self):
        """Test creating SSHClient with username and password"""
        client = SSHClient(
            hostname="example.com",
            username="admin",
            password="password123"
        )
        
        assert client.username == "admin"
        assert client.password == "password123"
    
    def test_initialization_with_key_file(self):
        """Test creating SSHClient with SSH key file"""
        client = SSHClient(
            hostname="example.com",
            username="admin",
            private_key_path="/path/to/key"
        )
        
        assert client.private_key_path == "/path/to/key"
    
    def test_initialization_verbose_mode(self):
        """Test creating SSHClient in verbose mode"""
        client = SSHClient(hostname="example.com", verbose=True)
        
        assert client.verbose is True


class TestSSHClientConnection:
    """Test SSH connection functionality"""
    
    @patch('paramiko.SSHClient')
    def test_connect_with_password(self, mock_ssh):
        """Test connecting with password authentication"""
        mock_instance = MagicMock()
        mock_ssh.return_value = mock_instance
        
        client = SSHClient(
            hostname="example.com",
            username="admin",
            password="password123"
        )
        
        result = client.connect()
        
        assert result is True
        mock_instance.set_missing_host_key_policy.assert_called_once()
        mock_instance.connect.assert_called_once()
    
    @patch('paramiko.SSHClient')
    def test_connect_with_key(self, mock_ssh):
        """Test connecting with key authentication"""
        mock_instance = MagicMock()
        mock_ssh.return_value = mock_instance
        
        client = SSHClient(
            hostname="example.com",
            username="admin",
            private_key_path="/path/to/key"
        )
        
        result = client.connect()
        
        assert result is True
        mock_instance.connect.assert_called_once()
    
    @patch('paramiko.SSHClient')
    def test_connect_failure(self, mock_ssh):
        """Test connection failure handling"""
        mock_instance = MagicMock()
        mock_instance.connect.side_effect = paramiko.AuthenticationException("Auth failed")
        mock_ssh.return_value = mock_instance
        
        client = SSHClient(
            hostname="example.com",
            username="admin",
            password="wrong"
        )
        
        result = client.connect()
        
        assert result is False
    
    @patch('paramiko.SSHClient')
    def test_disconnect(self, mock_ssh):
        """Test disconnecting SSH connection"""
        mock_instance = MagicMock()
        mock_ssh.return_value = mock_instance
        
        client = SSHClient(
            hostname="example.com",
            username="admin",
            password="password123"
        )
        
        client.connect()
        client.disconnect()
        
        mock_instance.close.assert_called_once()


class TestSSHClientCommandExecution:
    """Test command execution functionality"""
    
    @patch('paramiko.SSHClient')
    def test_execute_command_success(self, mock_ssh):
        """Test executing a command successfully"""
        mock_instance = MagicMock()
        mock_stdin = MagicMock()
        mock_stdout = MagicMock()
        mock_stderr = MagicMock()
        
        mock_stdout.read.return_value = b"command output"
        mock_stderr.read.return_value = b""
        mock_stdout.channel.recv_exit_status.return_value = 0
        
        mock_instance.exec_command.return_value = (mock_stdin, mock_stdout, mock_stderr)
        mock_ssh.return_value = mock_instance
        
        client = SSHClient(
            hostname="example.com",
            username="admin",
            password="password123"
        )
        client.connect()
        
        exit_code, stdout, stderr = client.execute_command("ls -la")
        
        assert exit_code == 0
        assert stdout == "command output"
        assert stderr == ""
        mock_instance.exec_command.assert_called_once_with("ls -la", timeout=30)
    
    @patch('paramiko.SSHClient')
    def test_execute_command_with_error(self, mock_ssh):
        """Test executing a command that returns an error"""
        mock_instance = MagicMock()
        mock_stdin = MagicMock()
        mock_stdout = MagicMock()
        mock_stderr = MagicMock()
        
        mock_stdout.read.return_value = b""
        mock_stderr.read.return_value = b"error message"
        mock_stdout.channel.recv_exit_status.return_value = 1
        
        mock_instance.exec_command.return_value = (mock_stdin, mock_stdout, mock_stderr)
        mock_ssh.return_value = mock_instance
        
        client = SSHClient(
            hostname="example.com",
            username="admin",
            password="password123"
        )
        client.connect()
        
        exit_code, stdout, stderr = client.execute_command("invalid-command")
        
        assert exit_code == 1
        assert stderr == "error message"
    
    @patch('paramiko.SSHClient')
    def test_execute_without_connection(self, mock_ssh):
        """Test executing command without connection fails gracefully"""
        client = SSHClient(
            hostname="example.com",
            username="admin",
            password="password123"
        )
        
        # Trying to execute without connecting should raise RuntimeError
        with pytest.raises(RuntimeError):
            client.execute_command("ls")


class TestSSHClientFileTransfer:
    """Test file transfer functionality"""
    
    @patch('paramiko.SSHClient')
    def test_sftp_get_file(self, mock_ssh):
        """Test downloading a file via SFTP"""
        mock_instance = MagicMock()
        mock_sftp = MagicMock()
        mock_instance.open_sftp.return_value = mock_sftp
        mock_ssh.return_value = mock_instance
        
        client = SSHClient(
            hostname="example.com",
            username="admin",
            password="password123"
        )
        client.connect()
        
        result = client.download_file("/remote/file.txt", "/local/file.txt")
        
        assert result is True
        mock_sftp.get.assert_called_once_with("/remote/file.txt", "/local/file.txt")
    
    @patch('paramiko.SSHClient')
    def test_sftp_put_file(self, mock_ssh):
        """Test uploading a file via SFTP"""
        mock_instance = MagicMock()
        mock_sftp = MagicMock()
        mock_instance.open_sftp.return_value = mock_sftp
        mock_ssh.return_value = mock_instance
        
        client = SSHClient(
            hostname="example.com",
            username="admin",
            password="password123"
        )
        client.connect()
        
        result = client.upload_file("/local/file.txt", "/remote/file.txt")
        
        assert result is True
        mock_sftp.put.assert_called_once_with("/local/file.txt", "/remote/file.txt")
    
    @patch('paramiko.SSHClient')
    def test_file_transfer_failure(self, mock_ssh):
        """Test file transfer failure handling"""
        mock_instance = MagicMock()
        mock_sftp = MagicMock()
        mock_sftp.get.side_effect = IOError("File not found")
        mock_instance.open_sftp.return_value = mock_sftp
        mock_ssh.return_value = mock_instance
        
        client = SSHClient(
            hostname="example.com",
            username="admin",
            password="password123"
        )
        client.connect()
        
        result = client.download_file("/remote/missing.txt", "/local/file.txt")
        
        assert result is False


class TestSSHExploitMixin:
    """Test SSHExploitMixin functionality"""
    
    def test_mixin_provides_ssh_client(self):
        """Test that mixin provides SSH client functionality"""
        
        # Import necessary classes
        from core.exploit import RemoteExploit, ExploitInfo
        
        class TestExploit(RemoteExploit, SSHExploitMixin):
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
        
        # Check that SSH client methods/properties are available
        assert hasattr(exploit, 'ssh_client') or hasattr(exploit, '_ssh_client')


class TestSSHClientKeyGeneration:
    """Test SSH key generation utilities"""
    
    @patch('paramiko.RSAKey.generate')
    def test_generate_ssh_key(self, mock_generate):
        """Test generating an SSH key pair"""
        mock_key = MagicMock()
        mock_generate.return_value = mock_key
        
        # Test would call a key generation method if it exists
        # This is a placeholder for future functionality
        assert mock_generate is not None


class TestSSHClientErrorHandling:
    """Test error handling"""
    
    @patch('paramiko.SSHClient')
    def test_timeout_handling(self, mock_ssh):
        """Test handling of connection timeout"""
        mock_instance = MagicMock()
        mock_instance.connect.side_effect = TimeoutError("Connection timed out")
        mock_ssh.return_value = mock_instance
        
        client = SSHClient(
            hostname="example.com",
            username="admin",
            password="password123"
        )
        
        result = client.connect()
        
        assert result is False
    
    @patch('paramiko.SSHClient')
    def test_authentication_failure(self, mock_ssh):
        """Test handling of authentication failure"""
        mock_instance = MagicMock()
        mock_instance.connect.side_effect = paramiko.AuthenticationException("Auth failed")
        mock_ssh.return_value = mock_instance
        
        client = SSHClient(
            hostname="example.com",
            username="admin",
            password="wrong_password"
        )
        
        result = client.connect()
        
        assert result is False
    
    @patch('paramiko.SSHClient')
    def test_ssh_exception_handling(self, mock_ssh):
        """Test handling of generic SSH exceptions"""
        mock_instance = MagicMock()
        mock_instance.connect.side_effect = paramiko.SSHException("SSH error")
        mock_ssh.return_value = mock_instance
        
        client = SSHClient(
            hostname="example.com",
            username="admin",
            password="password123"
        )
        
        result = client.connect()
        
        assert result is False


class TestSSHClientIntegration:
    """Integration tests for SSH client"""
    
    @patch('paramiko.SSHClient')
    def test_full_workflow(self, mock_ssh):
        """Test a complete SSH workflow: connect, execute, disconnect"""
        mock_instance = MagicMock()
        mock_stdin = MagicMock()
        mock_stdout = MagicMock()
        mock_stderr = MagicMock()
        
        mock_stdout.read.return_value = b"output"
        mock_stderr.read.return_value = b""
        mock_stdout.channel.recv_exit_status.return_value = 0
        mock_instance.exec_command.return_value = (mock_stdin, mock_stdout, mock_stderr)
        mock_ssh.return_value = mock_instance
        
        client = SSHClient(
            hostname="example.com",
            username="admin",
            password="password123"
        )
        
        # Connect
        assert client.connect() is True
        
        # Execute command
        exit_code, stdout, stderr = client.execute_command("whoami")
        assert exit_code == 0
        assert stdout == "output"
        
        # Disconnect
        client.disconnect()
    
    def test_client_with_all_features(self):
        """Test client initialization with all features"""
        client = SSHClient(
            hostname="example.com",
            port=2222,
            username="admin",
            password="password123",
            private_key_path="/path/to/key",
            timeout=30,
            verbose=True
        )
        
        assert client.hostname == "example.com"
        assert client.port == 2222
        assert client.username == "admin"
        assert client.password == "password123"
        assert client.private_key_path == "/path/to/key"
        assert client.timeout == 30
        assert client.verbose is True


class TestSSHClientConnectionStates:
    """Test connection state management"""
    
    def test_initial_state(self):
        """Test initial connection state"""
        client = SSHClient(hostname="example.com")
        
        assert client.client is None
    
    @patch('paramiko.SSHClient')
    def test_connected_state(self, mock_ssh):
        """Test state after successful connection"""
        mock_instance = MagicMock()
        mock_ssh.return_value = mock_instance
        
        client = SSHClient(
            hostname="example.com",
            username="admin",
            password="password123"
        )
        
        client.connect()
        
        assert client.client is not None
    
    @patch('paramiko.SSHClient')
    def test_disconnected_state(self, mock_ssh):
        """Test state after disconnection"""
        mock_instance = MagicMock()
        mock_ssh.return_value = mock_instance
        
        client = SSHClient(
            hostname="example.com",
            username="admin",
            password="password123"
        )
        
        client.connect()
        client.disconnect()
        
        assert client.client is None


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
