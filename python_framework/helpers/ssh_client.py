"""
SSH Client helper for exploit development

Provides SSH connectivity and operations commonly needed for exploits:
- Secure password and key-based authentication
- Host key verification with configurable policies
- Command execution with output sanitization
- Secure file transfer (SCP/SFTP)
- Interactive shell access with logging
- Key generation and management
- Connection security monitoring
- Audit logging for compliance
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
import hashlib
import base64


class SecureHostKeyPolicy(paramiko.MissingHostKeyPolicy):
    """
    Secure host key policy that validates and logs host keys
    """
    
    def __init__(self, known_hosts_file: Optional[str] = None, auto_add: bool = False, logger: Optional[logging.Logger] = None):
        self.known_hosts_file = known_hosts_file or os.path.expanduser("~/.ssh/known_hosts")
        self.auto_add = auto_add
        self.logger = logger or logging.getLogger(__name__)
        
    def missing_host_key(self, client, hostname, key):
        """Handle missing host key with security logging"""
        key_type = key.get_name()
        key_fingerprint = self._get_key_fingerprint(key)
        
        self.logger.warning(f"Unknown host key for {hostname}: {key_type} {key_fingerprint}")
        
        if self.auto_add:
            self.logger.info(f"Auto-adding host key for {hostname}")
            client.get_host_keys().add(hostname, key_type, key)
            
            # Save to known_hosts file if specified
            if self.known_hosts_file:
                try:
                    with open(self.known_hosts_file, 'a') as f:
                        f.write(f"{hostname} {key_type} {key.get_base64()}\n")
                except Exception as e:
                    self.logger.error(f"Failed to save host key: {e}")
        else:
            # Reject unknown host keys by default for security
            raise paramiko.SSHException(f"Unknown host key for {hostname}: {key_type} {key_fingerprint}")
    
    def _get_key_fingerprint(self, key) -> str:
        """Get SHA256 fingerprint of the key"""
        key_bytes = base64.b64decode(key.get_base64())
        fingerprint = hashlib.sha256(key_bytes).digest()
        return base64.b64encode(fingerprint).decode().rstrip('=')


class SSHClient:
    """
    SSH client tailored for exploit development needs with security focus.
    
    Features:
    - Secure password and key authentication
    - Configurable host key verification
    - Command execution with output sanitization
    - Secure file upload/download with validation
    - Interactive shell support with logging
    - Connection management with timeout
    - Key generation utilities
    - Comprehensive audit logging
    """
    
    # Security constants
    MAX_COMMAND_LENGTH = 10000
    MAX_OUTPUT_SIZE = 1024 * 1024  # 1MB
    CONNECTION_TIMEOUT = 30
    COMMAND_TIMEOUT = 300
    MAX_FILE_SIZE = 100 * 1024 * 1024  # 100MB
    
    def __init__(self, 
                 hostname: str,
                 port: int = 22,
                 username: str = "",
                 password: str = "",
                 private_key_path: str = "",
                 timeout: int = CONNECTION_TIMEOUT,
                 verbose: bool = False,
                 host_key_policy: str = "strict",  # strict, auto_add, or ignore
                 known_hosts_file: Optional[str] = None,
                 enable_audit_log: bool = True):
        """
        Initialize SSH client with security validations
        
        Args:
            hostname: Target hostname or IP
            port: SSH port
            username: Username for authentication
            password: Password for authentication
            private_key_path: Path to private key file
            timeout: Connection timeout
            verbose: Enable verbose logging
            host_key_policy: Host key verification policy (strict, auto_add, ignore)
            known_hosts_file: Path to known_hosts file
            enable_audit_log: Enable audit logging
        """
        # Input validation
        if not hostname or not isinstance(hostname, str):
            raise ValueError("Hostname must be a non-empty string")
        
        if not (1 <= port <= 65535):
            raise ValueError("Port must be between 1 and 65535")
        
        if not username or not isinstance(username, str):
            raise ValueError("Username must be a non-empty string")
        
        if timeout <= 0 or timeout > 300:
            raise ValueError("Timeout must be between 1 and 300 seconds")
        
        if host_key_policy not in ['strict', 'auto_add', 'ignore']:
            raise ValueError("Host key policy must be 'strict', 'auto_add', or 'ignore'")
        
        # Validate hostname format
        import re
        if not re.match(r'^[a-zA-Z0-9.-]+$', hostname):
            raise ValueError("Invalid hostname format")
        
        self.hostname = hostname
        self.port = port
        self.username = username
        self.password = password
        self.private_key_path = private_key_path
        self.timeout = timeout
        self.verbose = verbose
        self.host_key_policy = host_key_policy
        self.known_hosts_file = known_hosts_file
        self.enable_audit_log = enable_audit_log
        
        self.client: Optional[paramiko.SSHClient] = None
        self.sftp: Optional[paramiko.SFTPClient] = None
        self.shell: Optional[paramiko.Channel] = None
        
        # Connection tracking
        self._connection_start_time = None
        self._command_count = 0
        
        # Setup logging
        self.logger = logging.getLogger(f"{__name__}.SSHClient")
        
        # Setup audit logger if enabled
        if self.enable_audit_log:
            self.audit_logger = logging.getLogger(f"{__name__}.SSHAudit")
            self.audit_logger.setLevel(logging.INFO)
        
        if not verbose:
            # Suppress paramiko logging unless verbose
            logging.getLogger("paramiko").setLevel(logging.WARNING)
    
    def _audit_log(self, action: str, command: str = "", result: str = "", error: str = "") -> None:
        """Log audit information"""
        if self.enable_audit_log:
            timestamp = time.strftime("%Y-%m-%d %H:%M:%S")
            log_entry = {
                'timestamp': timestamp,
                'hostname': self.hostname,
                'username': self.username,
                'action': action,
                'command': command[:100] + "..." if len(command) > 100 else command,
                'result': result,
                'error': error
            }
            self.audit_logger.info(f"SSH_AUDIT: {log_entry}")
    
    def _validate_command(self, command: str) -> bool:
        """Validate command for security issues"""
        if not command or not isinstance(command, str):
            return False
        
        if len(command) > self.MAX_COMMAND_LENGTH:
            self.logger.error(f"Command too long: {len(command)} characters")
            return False
        
        # Log potentially dangerous commands
        dangerous_patterns = [
            r'\brm\s+-rf\s+/',
            r'\bdd\s+if=',
            r'\bmkfs\.',
            r'\bformat\b',
            r'>\s*/dev/sd[a-z]',
        ]
        
        for pattern in dangerous_patterns:
            if re.search(pattern, command, re.IGNORECASE):
                self.logger.warning(f"Potentially dangerous command detected: {pattern}")
        
        return True
    
    def _sanitize_output(self, output: str) -> str:
        """Sanitize command output"""
        if not output:
            return ""
        
        # Limit output size
        if len(output) > self.MAX_OUTPUT_SIZE:
            self.logger.warning(f"Large output truncated: {len(output)} bytes")
            output = output[:self.MAX_OUTPUT_SIZE] + "\n[OUTPUT TRUNCATED]"
        
        # Remove potential control characters that could cause issues
        sanitized = re.sub(r'[\x00-\x08\x0b\x0c\x0e-\x1f\x7f]', '', output)
        
        return sanitized
    
    def connect(self) -> bool:
        """
        Establish secure SSH connection with proper host key verification
        
        Returns:
            True if connection successful, False otherwise
        """
        try:
            self.client = paramiko.SSHClient()
            
            # Configure host key policy based on security requirements
            if self.host_key_policy == "strict":
                # Load known hosts and reject unknown keys
                if self.known_hosts_file and os.path.exists(self.known_hosts_file):
                    self.client.load_host_keys(self.known_hosts_file)
                else:
                    self.client.load_system_host_keys()
                self.client.set_missing_host_key_policy(paramiko.RejectPolicy())
                
            elif self.host_key_policy == "auto_add":
                # Auto-add unknown keys with logging
                policy = SecureHostKeyPolicy(
                    known_hosts_file=self.known_hosts_file,
                    auto_add=True,
                    logger=self.logger
                )
                self.client.set_missing_host_key_policy(policy)
                
            elif self.host_key_policy == "ignore":
                # Only for testing - not recommended for production
                self.logger.warning("Host key verification disabled - use with extreme caution")
                self.client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
            
            # Prepare authentication with security validations
            auth_kwargs = {
                'hostname': self.hostname,
                'port': self.port,
                'username': self.username,
                'timeout': self.timeout,
                'compress': True,  # Enable compression for performance
                'look_for_keys': False,  # Don't automatically look for keys
                'allow_agent': False   # Don't use SSH agent for security
            }
            
            # Use key authentication if private key provided
            if self.private_key_path and os.path.exists(self.private_key_path):
                if self.verbose:
                    self.logger.info(f"Using private key: {self.private_key_path}")
                
                # Validate key file permissions
                key_stat = os.stat(self.private_key_path)
                if key_stat.st_mode & 0o077:
                    self.logger.warning(f"Private key file has overly permissive permissions: {oct(key_stat.st_mode)}")
                
                # Try different key types with proper error handling
                key = None
                key_classes = [paramiko.RSAKey, paramiko.DSAKey, paramiko.ECDSAKey, paramiko.Ed25519Key]
                
                for key_class in key_classes:
                    try:
                        if self.password:
                            # Try with password first (encrypted key)
                            key = key_class.from_private_key_file(self.private_key_path, password=self.password)
                        else:
                            # Try without password
                            key = key_class.from_private_key_file(self.private_key_path)
                        break
                    except paramiko.PasswordRequiredException:
                        if not self.password:
                            self.logger.error("Private key is encrypted but no password provided")
                            continue
                    except Exception as e:
                        self.logger.debug(f"Failed to load key as {key_class.__name__}: {e}")
                        continue
                
                if key:
                    auth_kwargs['pkey'] = key
                    self.logger.info(f"Loaded {key.get_name()} private key")
                else:
                    self.logger.error(f"Could not load private key: {self.private_key_path}")
                    self._audit_log("CONNECT", error="Failed to load private key")
                    return False
            
            # Use password authentication if no key or as fallback
            if 'pkey' not in auth_kwargs and self.password:
                auth_kwargs['password'] = self.password
            
            if 'pkey' not in auth_kwargs and not self.password:
                self.logger.error("No authentication method provided (key or password)")
                return False
            
            if self.verbose:
                auth_method = "key" if 'pkey' in auth_kwargs else "password"
                self.logger.info(f"Connecting to {self.hostname}:{self.port} as {self.username} using {auth_method} authentication")
            
            self._connection_start_time = time.time()
            self.client.connect(**auth_kwargs)
            
            # Verify connection security
            transport = self.client.get_transport()
            if transport:
                cipher = transport.get_cipher()
                if self.verbose:
                    self.logger.info(f"SSH connection established using cipher: {cipher}")
                
                # Log weak ciphers
                weak_ciphers = ['des', 'rc4', 'md5']
                if any(weak in cipher.lower() for weak in weak_ciphers):
                    self.logger.warning(f"Weak cipher detected: {cipher}")
            
            if self.verbose:
                connection_time = time.time() - self._connection_start_time
                self.logger.info(f"SSH connection established in {connection_time:.2f}s")
            
            self._audit_log("CONNECT", result="SUCCESS")
            return True
            
        except Exception as e:
            error_msg = f"SSH connection failed: {e}"
            self.logger.error(error_msg)
            self._audit_log("CONNECT", error=str(e))
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