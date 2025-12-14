#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
Rex Socket Wrapper

Provides TCP/UDP socket functionality for Python-based Metasploit modules.
Aims to replicate Rex::Socket functionality from the Ruby framework.
"""

import socket
import ssl
import logging
from typing import Optional, Tuple, Union


class SocketError(Exception):
    """Base exception for socket operations."""
    pass


class TCPSocket:
    """
    TCP Socket wrapper for Metasploit modules.
    
    Provides simplified TCP socket operations with SSL/TLS support,
    timeout management, and error handling.
    """
    
    def __init__(self, rhost: str, rport: int, lhost: str = '0.0.0.0',
                 lport: int = 0, ssl: bool = False, timeout: int = 30,
                 context: Optional[ssl.SSLContext] = None):
        """
        Initialize TCP socket.
        
        Args:
            rhost: Remote host address
            rport: Remote port number
            lhost: Local bind address
            lport: Local bind port (0 for random)
            ssl: Use SSL/TLS if True
            timeout: Socket timeout in seconds
            context: SSL context (optional)
        """
        self.rhost = rhost
        self.rport = rport
        self.lhost = lhost
        self.lport = lport
        self.ssl = ssl
        self.timeout = timeout
        self.context = context
        
        self.sock: Optional[socket.socket] = None
        self._connected = False
    
    def connect(self) -> bool:
        """
        Connect to remote host.
        
        Returns:
            True if connection successful
            
        Raises:
            SocketError: If connection fails
        """
        try:
            # Create socket
            self.sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            self.sock.settimeout(self.timeout)
            
            # Bind to local address if specified
            if self.lhost or self.lport:
                self.sock.bind((self.lhost, self.lport))
            
            # Connect to remote host
            logging.debug(f"Connecting to {self.rhost}:{self.rport}")
            self.sock.connect((self.rhost, self.rport))
            
            # Wrap with SSL if requested
            if self.ssl:
                if self.context is None:
                    self.context = ssl.create_default_context()
                    self.context.check_hostname = False
                    self.context.verify_mode = ssl.CERT_NONE
                
                self.sock = self.context.wrap_socket(
                    self.sock,
                    server_hostname=self.rhost
                )
                logging.debug(f"SSL connection established")
            
            self._connected = True
            logging.debug(f"Connected to {self.rhost}:{self.rport}")
            return True
            
        except socket.error as e:
            error_msg = f"Failed to connect to {self.rhost}:{self.rport}: {e}"
            logging.error(error_msg)
            raise SocketError(error_msg)
    
    def send(self, data: Union[str, bytes]) -> int:
        """
        Send data to remote host.
        
        Args:
            data: Data to send (str or bytes)
            
        Returns:
            Number of bytes sent
            
        Raises:
            SocketError: If send fails
        """
        if not self._connected or not self.sock:
            raise SocketError("Socket not connected")
        
        try:
            # Convert string to bytes if needed
            if isinstance(data, str):
                data = data.encode()
            
            # sendall() returns None on success
            self.sock.sendall(data)
            logging.debug(f"Sent {len(data)} bytes")
            return len(data)
            
        except socket.error as e:
            error_msg = f"Failed to send data: {e}"
            logging.error(error_msg)
            raise SocketError(error_msg)
    
    def recv(self, size: int = 4096) -> bytes:
        """
        Receive data from remote host.
        
        Args:
            size: Maximum bytes to receive
            
        Returns:
            Received data as bytes
            
        Raises:
            SocketError: If receive fails
        """
        if not self._connected or not self.sock:
            raise SocketError("Socket not connected")
        
        try:
            data = self.sock.recv(size)
            logging.debug(f"Received {len(data)} bytes")
            return data
            
        except socket.error as e:
            error_msg = f"Failed to receive data: {e}"
            logging.error(error_msg)
            raise SocketError(error_msg)
    
    def recv_until(self, delimiter: bytes, max_size: int = 65536) -> bytes:
        """
        Receive data until delimiter is found.
        
        Args:
            delimiter: Byte sequence to stop at
            max_size: Maximum bytes to receive
            
        Returns:
            Received data including delimiter
            
        Raises:
            SocketError: If receive fails or max_size exceeded
        """
        if not self._connected or not self.sock:
            raise SocketError("Socket not connected")
        
        buffer = b''
        try:
            while len(buffer) < max_size:
                chunk = self.sock.recv(1)
                if not chunk:
                    break
                buffer += chunk
                if buffer.endswith(delimiter):
                    break
            
            if len(buffer) >= max_size:
                raise SocketError(f"Maximum buffer size ({max_size}) exceeded")
            
            return buffer
            
        except socket.error as e:
            error_msg = f"Failed to receive data: {e}"
            logging.error(error_msg)
            raise SocketError(error_msg)
    
    def close(self) -> None:
        """Close the socket connection."""
        if self.sock:
            try:
                self.sock.close()
                logging.debug(f"Socket closed")
            except socket.error as e:
                logging.warning(f"Error closing socket: {e}")
            finally:
                self._connected = False
                self.sock = None
    
    def __enter__(self):
        """Context manager entry - auto-connect."""
        self.connect()
        return self
    
    def __exit__(self, exc_type, exc_val, exc_tb):
        """Context manager exit - auto-close."""
        self.close()


class UDPSocket:
    """
    UDP Socket wrapper for Metasploit modules.
    
    Provides simplified UDP socket operations.
    """
    
    def __init__(self, lhost: str = '0.0.0.0', lport: int = 0, timeout: int = 30):
        """
        Initialize UDP socket.
        
        Args:
            lhost: Local bind address
            lport: Local bind port (0 for random)
            timeout: Socket timeout in seconds
        """
        self.lhost = lhost
        self.lport = lport
        self.timeout = timeout
        
        self.sock: Optional[socket.socket] = None
    
    def bind(self) -> bool:
        """
        Bind UDP socket to local address.
        
        Returns:
            True if bind successful
            
        Raises:
            SocketError: If bind fails
        """
        try:
            self.sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            self.sock.settimeout(self.timeout)
            self.sock.bind((self.lhost, self.lport))
            
            # Get actual port if 0 was specified
            self.lport = self.sock.getsockname()[1]
            
            logging.debug(f"UDP socket bound to {self.lhost}:{self.lport}")
            return True
            
        except socket.error as e:
            error_msg = f"Failed to bind UDP socket: {e}"
            logging.error(error_msg)
            raise SocketError(error_msg)
    
    def sendto(self, data: Union[str, bytes], rhost: str, rport: int) -> int:
        """
        Send data to remote host via UDP.
        
        Args:
            data: Data to send
            rhost: Remote host address
            rport: Remote port number
            
        Returns:
            Number of bytes sent
            
        Raises:
            SocketError: If send fails
        """
        if not self.sock:
            self.bind()
        
        try:
            # Convert string to bytes if needed
            if isinstance(data, str):
                data = data.encode()
            
            sent = self.sock.sendto(data, (rhost, rport))
            logging.debug(f"Sent {sent} bytes to {rhost}:{rport}")
            return sent
            
        except socket.error as e:
            error_msg = f"Failed to send UDP data: {e}"
            logging.error(error_msg)
            raise SocketError(error_msg)
    
    def recvfrom(self, size: int = 4096) -> Tuple[bytes, Tuple[str, int]]:
        """
        Receive data from any source.
        
        Args:
            size: Maximum bytes to receive
            
        Returns:
            Tuple of (data, (source_host, source_port))
            
        Raises:
            SocketError: If receive fails
        """
        if not self.sock:
            self.bind()
        
        try:
            data, addr = self.sock.recvfrom(size)
            logging.debug(f"Received {len(data)} bytes from {addr[0]}:{addr[1]}")
            return data, addr
            
        except socket.error as e:
            error_msg = f"Failed to receive UDP data: {e}"
            logging.error(error_msg)
            raise SocketError(error_msg)
    
    def close(self) -> None:
        """Close the UDP socket."""
        if self.sock:
            try:
                self.sock.close()
                logging.debug("UDP socket closed")
            except socket.error as e:
                logging.warning(f"Error closing UDP socket: {e}")
            finally:
                self.sock = None
    
    def __enter__(self):
        """Context manager entry - auto-bind."""
        self.bind()
        return self
    
    def __exit__(self, exc_type, exc_val, exc_tb):
        """Context manager exit - auto-close."""
        self.close()


def create_tcp_socket(rhost: str, rport: int, **kwargs) -> TCPSocket:
    """
    Create and connect a TCP socket.
    
    Args:
        rhost: Remote host
        rport: Remote port
        **kwargs: Additional socket parameters
        
    Returns:
        Connected TCPSocket instance
    """
    sock = TCPSocket(rhost, rport, **kwargs)
    sock.connect()
    return sock


def create_udp_socket(lhost: str = '0.0.0.0', lport: int = 0, **kwargs) -> UDPSocket:
    """
    Create and bind a UDP socket.
    
    Args:
        lhost: Local host to bind
        lport: Local port to bind
        **kwargs: Additional socket parameters
        
    Returns:
        Bound UDPSocket instance
    """
    sock = UDPSocket(lhost, lport, **kwargs)
    sock.bind()
    return sock
