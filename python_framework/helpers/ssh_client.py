"""
SSH Client helper for exploit development

Provides SSH connectivity and operations commonly needed for exploits:
- Password and key-based authentication
- Command execution
- File transfer (SCP/SFTP)
- Interactive shell access
- Key generation and management
"""

import paramiko
import socket
import time
import threading
from typing import Optional, Dict, Any, Tuple, List, Union
from pathlib import Path
import logging
from io import StringIO
import os


class SSHClient:
    """
    SSH client tailored for exploit development needs.
    
    Features:
    - Password and key authentication
    - Command execution with output capture
    - File upload/download
    - Interactive shell support
    - Connection management
    - Key generation utilities
    """
    
    def __init__(self, 
                 hostname: str,
                 port: int = 22,
                 username: str = "",
                 password: str = "",
                 private_key_path: str = "",
                 timeout: int = 30,
                 verbose: bool = False):
        """
        Initialize SSH client
        
        Args:
            hostname: Target hostname or IP
            port: SSH port
            username: Username for authentication
            password: Password for authentication
            private_key_path: Path to private key file
            timeout: Connection timeout
            verbose: Enable verbose logging
        """
        self.hostname = hostname
        self.port = port
        self.username = username
        self.password = password
        self.private_key_path = private_key_path
        self.timeout = timeout
        self.verbose = verbose
        
        self.client: Optional[paramiko.SSHClient] = None
        self.sftp: Optional[paramiko.SFTPClient] = None
        self.shell: Optional[paramiko.Channel] = None
        
        # Setup logging
        self.logger = logging.getLogger(f"{__name__}.SSHClient")
        
        if not verbose:
            # Suppress paramiko logging unless verbose
            logging.getLogger("paramiko").setLevel(logging.WARNING)
    
    def connect(self) -> bool:
        """
        Establish SSH connection
        
        Returns:
            True if connection successful, False otherwise
        """
        try:
            self.client = paramiko.SSHClient()
            self.client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
            
            # Prepare authentication
            auth_kwargs = {
                'hostname': self.hostname,
                'port': self.port,
                'username': self.username,
                'timeout': self.timeout
            }
            
            # Use key authentication if private key provided
            if self.private_key_path and os.path.exists(self.private_key_path):
                if self.verbose:
                    self.logger.info(f"Using private key: {self.private_key_path}")
                
                # Try different key types
                key = None
                for key_class in [paramiko.RSAKey, paramiko.DSAKey, paramiko.ECDSAKey, paramiko.Ed25519Key]:
                    try:
                        key = key_class.from_private_key_file(self.private_key_path)
                        break
                    except paramiko.PasswordRequiredException:
                        # Key is encrypted, try with password
                        if self.password:
                            try:
                                key = key_class.from_private_key_file(self.private_key_path, password=self.password)
                                break
                            except:
                                continue
                    except:
                        continue
                
                if key:
                    auth_kwargs['pkey'] = key
                else:
                    self.logger.error(f"Could not load private key: {self.private_key_path}")
                    return False
            
            # Use password authentication if no key or as fallback
            if 'pkey' not in auth_kwargs and self.password:
                auth_kwargs['password'] = self.password
            
            if self.verbose:
                self.logger.info(f"Connecting to {self.hostname}:{self.port} as {self.username}")
            
            self.client.connect(**auth_kwargs)
            
            if self.verbose:
                self.logger.info("SSH connection established")
            
            return True
            
        except Exception as e:
            self.logger.error(f"SSH connection failed: {e}")
            return False
    
    def disconnect(self) -> None:
        """Close SSH connection and cleanup resources"""
        if self.shell:
            self.shell.close()
            self.shell = None
        
        if self.sftp:
            self.sftp.close()
            self.sftp = None
        
        if self.client:
            self.client.close()
            self.client = None
        
        if self.verbose:
            self.logger.info("SSH connection closed")
    
    def execute_command(self, command: str, timeout: Optional[int] = None) -> Tuple[int, str, str]:
        """
        Execute a command and return results
        
        Args:
            command: Command to execute
            timeout: Command timeout (uses connection timeout if None)
            
        Returns:
            Tuple of (exit_code, stdout, stderr)
        """
        if not self.client:
            raise RuntimeError("Not connected to SSH server")
        
        cmd_timeout = timeout or self.timeout
        
        if self.verbose:
            self.logger.info(f"Executing command: {command}")
        
        try:
            stdin, stdout, stderr = self.client.exec_command(command, timeout=cmd_timeout)
            
            # Read output
            stdout_data = stdout.read().decode('utf-8', errors='ignore')
            stderr_data = stderr.read().decode('utf-8', errors='ignore')
            exit_code = stdout.channel.recv_exit_status()
            
            if self.verbose:
                self.logger.info(f"Command exit code: {exit_code}")
                if stdout_data:
                    self.logger.debug(f"STDOUT: {stdout_data[:200]}...")
                if stderr_data:
                    self.logger.debug(f"STDERR: {stderr_data[:200]}...")
            
            return exit_code, stdout_data, stderr_data
            
        except Exception as e:
            self.logger.error(f"Command execution failed: {e}")
            return -1, "", str(e)
    
    def upload_file(self, local_path: str, remote_path: str) -> bool:
        """
        Upload file to remote server
        
        Args:
            local_path: Local file path
            remote_path: Remote file path
            
        Returns:
            True if upload successful, False otherwise
        """
        if not self.client:
            raise RuntimeError("Not connected to SSH server")
        
        try:
            if not self.sftp:
                self.sftp = self.client.open_sftp()
            
            if self.verbose:
                self.logger.info(f"Uploading {local_path} to {remote_path}")
            
            self.sftp.put(local_path, remote_path)
            
            if self.verbose:
                self.logger.info("File upload completed")
            
            return True
            
        except Exception as e:
            self.logger.error(f"File upload failed: {e}")
            return False
    
    def download_file(self, remote_path: str, local_path: str) -> bool:
        """
        Download file from remote server
        
        Args:
            remote_path: Remote file path
            local_path: Local file path
            
        Returns:
            True if download successful, False otherwise
        """
        if not self.client:
            raise RuntimeError("Not connected to SSH server")
        
        try:
            if not self.sftp:
                self.sftp = self.client.open_sftp()
            
            if self.verbose:
                self.logger.info(f"Downloading {remote_path} to {local_path}")
            
            self.sftp.get(remote_path, local_path)
            
            if self.verbose:
                self.logger.info("File download completed")
            
            return True
            
        except Exception as e:
            self.logger.error(f"File download failed: {e}")
            return False
    
    def start_interactive_shell(self) -> Optional[paramiko.Channel]:
        """
        Start an interactive shell session
        
        Returns:
            Channel object for shell interaction, None if failed
        """
        if not self.client:
            raise RuntimeError("Not connected to SSH server")
        
        try:
            self.shell = self.client.invoke_shell()
            
            if self.verbose:
                self.logger.info("Interactive shell started")
            
            return self.shell
            
        except Exception as e:
            self.logger.error(f"Failed to start interactive shell: {e}")
            return None
    
    def shell_send(self, data: str) -> None:
        """Send data to interactive shell"""
        if not self.shell:
            raise RuntimeError("Interactive shell not started")
        
        self.shell.send(data)
    
    def shell_recv(self, timeout: int = 1) -> str:
        """Receive data from interactive shell"""
        if not self.shell:
            raise RuntimeError("Interactive shell not started")
        
        self.shell.settimeout(timeout)
        try:
            return self.shell.recv(4096).decode('utf-8', errors='ignore')
        except socket.timeout:
            return ""
    
    def add_ssh_key(self, public_key: str, authorized_keys_path: str = "~/.ssh/authorized_keys") -> bool:
        """
        Add SSH public key to authorized_keys file
        
        Args:
            public_key: SSH public key string
            authorized_keys_path: Path to authorized_keys file
            
        Returns:
            True if key added successfully, False otherwise
        """
        try:
            # Ensure .ssh directory exists
            exit_code, _, _ = self.execute_command("mkdir -p ~/.ssh && chmod 700 ~/.ssh")
            if exit_code != 0:
                return False
            
            # Add key to authorized_keys
            escaped_key = public_key.replace('"', '\\"')
            command = f'echo "{escaped_key}" >> {authorized_keys_path} && chmod 600 {authorized_keys_path}'
            exit_code, _, _ = self.execute_command(command)
            
            return exit_code == 0
            
        except Exception as e:
            self.logger.error(f"Failed to add SSH key: {e}")
            return False


class SSHKeyGenerator:
    """Utility class for SSH key generation"""
    
    @staticmethod
    def generate_rsa_key_pair(key_size: int = 2048) -> Tuple[str, str]:
        """
        Generate RSA key pair
        
        Args:
            key_size: RSA key size in bits
            
        Returns:
            Tuple of (private_key_pem, public_key_openssh)
        """
        # Generate private key
        private_key = paramiko.RSAKey.generate(key_size)
        
        # Get private key in PEM format
        private_key_file = StringIO()
        private_key.write_private_key(private_key_file)
        private_key_pem = private_key_file.getvalue()
        private_key_file.close()
        
        # Get public key in OpenSSH format
        public_key_openssh = f"ssh-rsa {private_key.get_base64()}"
        
        return private_key_pem, public_key_openssh
    
    @staticmethod
    def save_key_pair(private_key_pem: str, public_key_openssh: str, 
                     private_key_path: str, public_key_path: str) -> None:
        """
        Save key pair to files
        
        Args:
            private_key_pem: Private key in PEM format
            public_key_openssh: Public key in OpenSSH format
            private_key_path: Path to save private key
            public_key_path: Path to save public key
        """
        # Save private key
        with open(private_key_path, 'w') as f:
            f.write(private_key_pem)
        os.chmod(private_key_path, 0o600)
        
        # Save public key
        with open(public_key_path, 'w') as f:
            f.write(public_key_openssh)
        os.chmod(public_key_path, 0o644)


class SSHExploitMixin:
    """
    Mixin class to add SSH client functionality to exploits.
    
    This mixin provides convenient SSH methods that automatically
    use the exploit's configuration options.
    """
    
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self._ssh_client: Optional[SSHClient] = None
    
    @property
    def ssh_client(self) -> SSHClient:
        """Get or create SSH client instance"""
        if self._ssh_client is None:
            host = self.get_option('RHOSTS', 'localhost')
            
            # Handle multiple hosts - use first one
            if ',' in host:
                host = host.split(',')[0].strip()
            
            self._ssh_client = SSHClient(
                hostname=host,
                port=self.get_option('SSHPORT', 22),
                username=self.get_option('USERNAME', ''),
                password=self.get_option('PASSWORD', ''),
                private_key_path=self.get_option('PRIV_KEY_FILE', ''),
                timeout=self.get_option('SSH_TIMEOUT', 30),
                verbose=self.get_option('VERBOSE', False)
            )
        
        return self._ssh_client
    
    def ssh_connect(self) -> bool:
        """Connect to SSH server using exploit configuration"""
        return self.ssh_client.connect()
    
    def ssh_execute(self, command: str, timeout: Optional[int] = None) -> Tuple[int, str, str]:
        """Execute SSH command using exploit configuration"""
        return self.ssh_client.execute_command(command, timeout)
    
    def ssh_upload(self, local_path: str, remote_path: str) -> bool:
        """Upload file via SSH using exploit configuration"""
        return self.ssh_client.upload_file(local_path, remote_path)
    
    def ssh_download(self, remote_path: str, local_path: str) -> bool:
        """Download file via SSH using exploit configuration"""
        return self.ssh_client.download_file(remote_path, local_path)
    
    def cleanup_ssh(self) -> None:
        """Clean up SSH client resources"""
        if self._ssh_client:
            self._ssh_client.disconnect()
            self._ssh_client = None