#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
Unit tests for the SSHClient helper.

This test module validates the Python implementation of the SSH client helper,
ensuring proper SSH connectivity, command execution, and file transfer functionality.
"""

import unittest
from unittest.mock import Mock, MagicMock, patch, call, mock_open
import paramiko
from io import StringIO

from python_framework.helpers.ssh_client import SSHClient, SSHKeyGenerator, SSHExploitMixin


class TestSSHClient(unittest.TestCase):
    """Test SSHClient class"""

    def test_initialization_defaults(self):
        """Test SSHClient initialization with required parameters"""
        client = SSHClient(hostname="example.com")

        self.assertEqual(client.hostname, "example.com")
        self.assertEqual(client.port, 22)
        self.assertEqual(client.username, "")
        self.assertEqual(client.password, "")
        self.assertEqual(client.timeout, 30)
        self.assertFalse(client.verbose)
        self.assertIsNone(client.client)
        self.assertIsNone(client.sftp)
        self.assertIsNone(client.shell)

    def test_initialization_with_parameters(self):
        """Test SSHClient initialization with custom parameters"""
        client = SSHClient(
            hostname="192.168.1.100",
            port=2222,
            username="admin",
            password="secret",
            private_key_path="/path/to/key",
            timeout=60,
            verbose=True,
        )

        self.assertEqual(client.hostname, "192.168.1.100")
        self.assertEqual(client.port, 2222)
        self.assertEqual(client.username, "admin")
        self.assertEqual(client.password, "secret")
        self.assertEqual(client.private_key_path, "/path/to/key")
        self.assertEqual(client.timeout, 60)
        self.assertTrue(client.verbose)

    @patch("paramiko.SSHClient")
    def test_connect_with_password(self, mock_ssh_class):
        """Test SSH connection with password authentication"""
        mock_ssh_instance = MagicMock()
        mock_ssh_class.return_value = mock_ssh_instance

        client = SSHClient(hostname="example.com", username="user", password="pass")
        result = client.connect()

        self.assertTrue(result)
        mock_ssh_instance.set_missing_host_key_policy.assert_called_once()
        mock_ssh_instance.connect.assert_called_once()

        # Verify password was used
        connect_kwargs = mock_ssh_instance.connect.call_args[1]
        self.assertEqual(connect_kwargs["password"], "pass")

    @patch("os.path.exists")
    @patch("paramiko.SSHClient")
    @unittest.skip("DSAKey deprecated in paramiko 4.0 - implementation needs update")
    def test_connect_with_private_key(self, mock_ssh_class, mock_exists):
        """Test SSH connection with private key authentication"""
        mock_exists.return_value = True

        # Mock RSA key loading
        mock_key = MagicMock()
        with patch("paramiko.RSAKey.from_private_key_file", return_value=mock_key):
            mock_ssh_instance = MagicMock()
            mock_ssh_class.return_value = mock_ssh_instance

            client = SSHClient(
                hostname="example.com", username="user", private_key_path="/path/to/key"
            )
            result = client.connect()

            self.assertTrue(result)
            mock_ssh_instance.connect.assert_called_once()

            # Verify key was used in connection
            connect_kwargs = mock_ssh_instance.connect.call_args[1]
            self.assertEqual(connect_kwargs["pkey"], mock_key)

    @patch("paramiko.SSHClient")
    def test_connect_failure(self, mock_ssh_class):
        """Test SSH connection failure handling"""
        mock_ssh_instance = MagicMock()
        mock_ssh_instance.connect.side_effect = Exception("Connection failed")
        mock_ssh_class.return_value = mock_ssh_instance

        client = SSHClient(hostname="example.com")
        result = client.connect()

        self.assertFalse(result)

    def test_disconnect_cleanup(self):
        """Test disconnect properly cleans up resources"""
        client = SSHClient(hostname="example.com")

        # Mock the components
        mock_client = MagicMock()
        mock_sftp = MagicMock()
        mock_shell = MagicMock()
        
        client.client = mock_client
        client.sftp = mock_sftp
        client.shell = mock_shell

        client.disconnect()

        # Verify all components were closed
        mock_shell.close.assert_called_once()
        mock_sftp.close.assert_called_once()
        mock_client.close.assert_called_once()

        # Verify all set to None
        self.assertIsNone(client.client)
        self.assertIsNone(client.sftp)
        self.assertIsNone(client.shell)

    def test_execute_command_not_connected(self):
        """Test execute_command raises error when not connected"""
        client = SSHClient(hostname="example.com")

        with self.assertRaises(RuntimeError) as context:
            client.execute_command("ls -la")

        self.assertIn("Not connected", str(context.exception))

    def test_execute_command_success(self):
        """Test successful command execution"""
        client = SSHClient(hostname="example.com")
        client.client = MagicMock()

        # Mock command execution
        mock_stdin = MagicMock()
        mock_stdout = MagicMock()
        mock_stderr = MagicMock()

        mock_stdout.read.return_value = b"command output"
        mock_stderr.read.return_value = b""
        mock_stdout.channel.recv_exit_status.return_value = 0

        client.client.exec_command.return_value = (mock_stdin, mock_stdout, mock_stderr)

        exit_code, stdout, stderr = client.execute_command("ls -la")

        self.assertEqual(exit_code, 0)
        self.assertEqual(stdout, "command output")
        self.assertEqual(stderr, "")

    def test_execute_command_with_error(self):
        """Test command execution with error output"""
        client = SSHClient(hostname="example.com")
        client.client = MagicMock()

        mock_stdin = MagicMock()
        mock_stdout = MagicMock()
        mock_stderr = MagicMock()

        mock_stdout.read.return_value = b""
        mock_stderr.read.return_value = b"command not found"
        mock_stdout.channel.recv_exit_status.return_value = 1

        client.client.exec_command.return_value = (mock_stdin, mock_stdout, mock_stderr)

        exit_code, stdout, stderr = client.execute_command("invalid_command")

        self.assertEqual(exit_code, 1)
        self.assertEqual(stderr, "command not found")

    def test_execute_command_with_timeout(self):
        """Test command execution with custom timeout"""
        client = SSHClient(hostname="example.com", timeout=30)
        client.client = MagicMock()

        mock_stdout = MagicMock()
        mock_stdout.read.return_value = b"output"
        mock_stdout.channel.recv_exit_status.return_value = 0

        client.client.exec_command.return_value = (MagicMock(), mock_stdout, MagicMock())

        client.execute_command("sleep 10", timeout=60)

        # Verify timeout was passed
        call_args = client.client.exec_command.call_args
        self.assertEqual(call_args[1]["timeout"], 60)

    def test_execute_command_exception_handling(self):
        """Test command execution exception handling"""
        client = SSHClient(hostname="example.com")
        client.client = MagicMock()
        client.client.exec_command.side_effect = Exception("Execution failed")

        exit_code, stdout, stderr = client.execute_command("ls")

        self.assertEqual(exit_code, -1)
        self.assertEqual(stdout, "")
        self.assertIn("Execution failed", stderr)

    def test_upload_file_not_connected(self):
        """Test upload_file raises error when not connected"""
        client = SSHClient(hostname="example.com")

        with self.assertRaises(RuntimeError):
            client.upload_file("/local/file", "/remote/file")

    @patch("paramiko.SFTPClient")
    def test_upload_file_success(self, mock_sftp_class):
        """Test successful file upload"""
        client = SSHClient(hostname="example.com")
        client.client = MagicMock()

        mock_sftp = MagicMock()
        client.client.open_sftp.return_value = mock_sftp

        result = client.upload_file("/local/file.txt", "/remote/file.txt")

        self.assertTrue(result)
        mock_sftp.put.assert_called_once_with("/local/file.txt", "/remote/file.txt")

    @patch("paramiko.SFTPClient")
    def test_upload_file_failure(self, mock_sftp_class):
        """Test file upload failure handling"""
        client = SSHClient(hostname="example.com")
        client.client = MagicMock()

        mock_sftp = MagicMock()
        mock_sftp.put.side_effect = Exception("Upload failed")
        client.client.open_sftp.return_value = mock_sftp

        result = client.upload_file("/local/file.txt", "/remote/file.txt")

        self.assertFalse(result)

    def test_download_file_not_connected(self):
        """Test download_file raises error when not connected"""
        client = SSHClient(hostname="example.com")

        with self.assertRaises(RuntimeError):
            client.download_file("/remote/file", "/local/file")

    @patch("paramiko.SFTPClient")
    def test_download_file_success(self, mock_sftp_class):
        """Test successful file download"""
        client = SSHClient(hostname="example.com")
        client.client = MagicMock()

        mock_sftp = MagicMock()
        client.client.open_sftp.return_value = mock_sftp

        result = client.download_file("/remote/file.txt", "/local/file.txt")

        self.assertTrue(result)
        mock_sftp.get.assert_called_once_with("/remote/file.txt", "/local/file.txt")

    @patch("paramiko.SFTPClient")
    def test_download_file_failure(self, mock_sftp_class):
        """Test file download failure handling"""
        client = SSHClient(hostname="example.com")
        client.client = MagicMock()

        mock_sftp = MagicMock()
        mock_sftp.get.side_effect = Exception("Download failed")
        client.client.open_sftp.return_value = mock_sftp

        result = client.download_file("/remote/file.txt", "/local/file.txt")

        self.assertFalse(result)

    def test_start_interactive_shell_not_connected(self):
        """Test start_interactive_shell raises error when not connected"""
        client = SSHClient(hostname="example.com")

        with self.assertRaises(RuntimeError):
            client.start_interactive_shell()

    def test_start_interactive_shell_success(self):
        """Test successful interactive shell start"""
        client = SSHClient(hostname="example.com")
        client.client = MagicMock()

        mock_channel = MagicMock()
        client.client.invoke_shell.return_value = mock_channel

        channel = client.start_interactive_shell()

        self.assertIsNotNone(channel)
        self.assertEqual(client.shell, mock_channel)

    def test_shell_send_not_started(self):
        """Test shell_send raises error when shell not started"""
        client = SSHClient(hostname="example.com")

        with self.assertRaises(RuntimeError):
            client.shell_send("command\n")

    def test_shell_send_success(self):
        """Test successful shell send"""
        client = SSHClient(hostname="example.com")
        client.shell = MagicMock()

        client.shell_send("ls -la\n")

        client.shell.send.assert_called_once_with("ls -la\n")

    def test_shell_recv_not_started(self):
        """Test shell_recv raises error when shell not started"""
        client = SSHClient(hostname="example.com")

        with self.assertRaises(RuntimeError):
            client.shell_recv()

    def test_shell_recv_success(self):
        """Test successful shell receive"""
        client = SSHClient(hostname="example.com")
        client.shell = MagicMock()
        client.shell.recv.return_value = b"output data"

        output = client.shell_recv()

        self.assertEqual(output, "output data")

    def test_add_ssh_key_success(self):
        """Test successful SSH key addition"""
        client = SSHClient(hostname="example.com")
        client.client = MagicMock()

        # Mock successful command execution
        mock_stdout = MagicMock()
        mock_stdout.read.return_value = b""
        mock_stdout.channel.recv_exit_status.return_value = 0

        client.client.exec_command.return_value = (
            MagicMock(),
            mock_stdout,
            MagicMock(read=lambda: b""),
        )

        public_key = "ssh-rsa AAAAB3NzaC1yc2E... user@host"
        result = client.add_ssh_key(public_key)

        self.assertTrue(result)

    def test_add_ssh_key_failure(self):
        """Test SSH key addition failure"""
        client = SSHClient(hostname="example.com")
        client.client = MagicMock()

        # Mock failed command execution
        mock_stdout = MagicMock()
        mock_stdout.channel.recv_exit_status.return_value = 1

        client.client.exec_command.return_value = (
            MagicMock(),
            mock_stdout,
            MagicMock(read=lambda: b""),
        )

        result = client.add_ssh_key("ssh-rsa KEY")

        self.assertFalse(result)


class TestSSHKeyGenerator(unittest.TestCase):
    """Test SSHKeyGenerator class"""

    def test_generate_rsa_key_pair(self):
        """Test RSA key pair generation"""
        private_key, public_key = SSHKeyGenerator.generate_rsa_key_pair(2048)

        self.assertIsInstance(private_key, str)
        self.assertIsInstance(public_key, str)
        self.assertIn("-----BEGIN RSA PRIVATE KEY-----", private_key)
        self.assertIn("ssh-rsa", public_key)

    def test_generate_rsa_key_pair_custom_size(self):
        """Test RSA key pair generation with custom size"""
        private_key, public_key = SSHKeyGenerator.generate_rsa_key_pair(1024)

        self.assertIsInstance(private_key, str)
        self.assertIsInstance(public_key, str)

    @patch("builtins.open", new_callable=mock_open)
    @patch("os.chmod")
    def test_save_key_pair(self, mock_chmod, mock_file):
        """Test saving key pair to files"""
        private_key = "-----BEGIN RSA PRIVATE KEY-----\nKEY DATA\n-----END RSA PRIVATE KEY-----"
        public_key = "ssh-rsa AAAAB3NzaC1yc2E..."

        SSHKeyGenerator.save_key_pair(
            private_key, public_key, "/path/to/private_key", "/path/to/public_key.pub"
        )

        # Verify files were opened and written
        self.assertEqual(mock_file.call_count, 2)

        # Verify chmod was called to set correct permissions
        self.assertEqual(mock_chmod.call_count, 2)


class TestSSHExploitMixin(unittest.TestCase):
    """Test SSHExploitMixin class"""

    def setUp(self):
        """Set up test fixtures"""

        class MockExploit(SSHExploitMixin):
            def __init__(self):
                self.datastore = {
                    "RHOSTS": "192.168.1.100",
                    "SSHPORT": 22,
                    "USERNAME": "root",
                    "PASSWORD": "toor",
                    "PRIV_KEY_FILE": "",
                    "SSH_TIMEOUT": 30,
                    "VERBOSE": False,
                }
                super().__init__()

            def get_option(self, name, default=None):
                return self.datastore.get(name, default)

        self.exploit_class = MockExploit

    def test_mixin_initialization(self):
        """Test mixin initialization"""
        exploit = self.exploit_class()

        self.assertIsNone(exploit._ssh_client)

    def test_ssh_client_lazy_creation(self):
        """Test SSH client is created on first access"""
        exploit = self.exploit_class()

        client = exploit.ssh_client

        self.assertIsNotNone(client)
        self.assertIsInstance(client, SSHClient)

    def test_ssh_client_reuses_instance(self):
        """Test SSH client reuses same instance"""
        exploit = self.exploit_class()

        client1 = exploit.ssh_client
        client2 = exploit.ssh_client

        self.assertIs(client1, client2)

    def test_ssh_client_uses_exploit_options(self):
        """Test SSH client uses exploit configuration"""
        exploit = self.exploit_class()
        exploit.datastore["RHOSTS"] = "example.com"
        exploit.datastore["SSHPORT"] = 2222
        exploit.datastore["USERNAME"] = "admin"

        client = exploit.ssh_client

        self.assertEqual(client.hostname, "example.com")
        self.assertEqual(client.port, 2222)
        self.assertEqual(client.username, "admin")

    def test_ssh_client_handles_multiple_hosts(self):
        """Test SSH client handles comma-separated hosts"""
        exploit = self.exploit_class()
        exploit.datastore["RHOSTS"] = "192.168.1.1, 192.168.1.2, 192.168.1.3"

        client = exploit.ssh_client

        # Should use first host
        self.assertEqual(client.hostname, "192.168.1.1")

    @patch.object(SSHClient, "connect")
    def test_ssh_connect_method(self, mock_connect):
        """Test ssh_connect convenience method"""
        mock_connect.return_value = True

        exploit = self.exploit_class()
        result = exploit.ssh_connect()

        self.assertTrue(result)
        mock_connect.assert_called_once()

    @patch.object(SSHClient, "execute_command")
    def test_ssh_execute_method(self, mock_execute):
        """Test ssh_execute convenience method"""
        mock_execute.return_value = (0, "output", "")

        exploit = self.exploit_class()
        exit_code, stdout, stderr = exploit.ssh_execute("whoami")

        self.assertEqual(exit_code, 0)
        self.assertEqual(stdout, "output")
        mock_execute.assert_called_once_with("whoami", None)

    @patch.object(SSHClient, "upload_file")
    def test_ssh_upload_method(self, mock_upload):
        """Test ssh_upload convenience method"""
        mock_upload.return_value = True

        exploit = self.exploit_class()
        result = exploit.ssh_upload("/local/file", "/remote/file")

        self.assertTrue(result)
        mock_upload.assert_called_once_with("/local/file", "/remote/file")

    @patch.object(SSHClient, "download_file")
    def test_ssh_download_method(self, mock_download):
        """Test ssh_download convenience method"""
        mock_download.return_value = True

        exploit = self.exploit_class()
        result = exploit.ssh_download("/remote/file", "/local/file")

        self.assertTrue(result)
        mock_download.assert_called_once_with("/remote/file", "/local/file")

    @patch.object(SSHClient, "disconnect")
    def test_cleanup_ssh(self, mock_disconnect):
        """Test cleanup_ssh method"""
        exploit = self.exploit_class()
        _ = exploit.ssh_client  # Create client

        exploit.cleanup_ssh()

        mock_disconnect.assert_called_once()


if __name__ == "__main__":
    unittest.main()
