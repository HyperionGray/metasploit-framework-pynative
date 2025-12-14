#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
Network Route Management

This module provides the Route class for representing logical network routes
in the Metasploit Python Framework. It is a Python equivalent of the Ruby
Rex::Post::Meterpreter::Extensions::Stdapi::Net::Route class.

The Route class supports both IPv4 and IPv6 addresses and provides methods
for route representation and formatting.
"""

import ipaddress
from typing import Union, Optional


class Route:
    """
    Represents a logical network route.
    
    This class handles network routing information including subnet, netmask,
    gateway, interface, and metric. It supports both IPv4 and IPv6 addresses.
    
    Attributes:
        subnet (str): The subnet address for this route
        netmask (str): The netmask for the subnet
        gateway (str): The gateway address for the route
        interface (str): The interface name for the route
        metric (int): The routing metric (priority)
    """
    
    def __init__(
        self,
        subnet: Union[str, bytes],
        netmask: Union[str, bytes],
        gateway: Union[str, bytes],
        interface: str = '',
        metric: int = 0
    ):
        """
        Initialize a route instance.
        
        Args:
            subnet: The subnet address (as string or bytes in network byte order)
            netmask: The netmask (as string or bytes in network byte order)
            gateway: The gateway address (as string or bytes in network byte order)
            interface: The interface name (default: '')
            metric: The routing metric (default: 0)
        
        Examples:
            >>> route = Route('192.168.1.0', '255.255.255.0', '192.168.1.1')
            >>> route = Route(b'\\xc0\\xa8\\x01\\x00', b'\\xff\\xff\\xff\\x00', b'\\xc0\\xa8\\x01\\x01')
        """
        self.subnet = self._parse_address(subnet)
        self.netmask = self._parse_address(netmask)
        self.gateway = self._parse_address(gateway)
        self.interface = interface
        self.metric = metric
    
    def _parse_address(self, addr: Union[str, bytes]) -> str:
        """
        Parse an address from either string or network byte order bytes.
        
        This method mimics Ruby's IPAddr.new_ntoh(addr).to_s functionality,
        converting network byte order (big-endian) bytes to a string representation.
        
        Args:
            addr: The address as string or bytes
            
        Returns:
            str: The address as a string
            
        Raises:
            ValueError: If the address format is invalid
        """
        if isinstance(addr, str):
            # Validate the string address
            try:
                ipaddress.ip_address(addr)
                return addr
            except ValueError as e:
                raise ValueError(f"Invalid IP address string: {addr}") from e
        
        elif isinstance(addr, bytes):
            # Convert from network byte order (big-endian)
            try:
                if len(addr) == 4:
                    # IPv4 address
                    return str(ipaddress.IPv4Address(addr))
                elif len(addr) == 16:
                    # IPv6 address
                    return str(ipaddress.IPv6Address(addr))
                else:
                    raise ValueError(f"Invalid address length: {len(addr)} bytes")
            except (ValueError, ipaddress.AddressValueError) as e:
                raise ValueError(f"Invalid IP address bytes: {addr!r}") from e
        
        else:
            raise TypeError(f"Address must be str or bytes, not {type(addr).__name__}")
    
    def pretty(self) -> str:
        """
        Provides a pretty formatted version of the route.
        
        This mimics the Ruby sprintf format:
        "%16s %16s %16s %d %16s" for subnet, netmask, gateway, metric, interface
        
        Returns:
            str: A formatted string representation of the route
            
        Example:
            >>> route = Route('192.168.1.0', '255.255.255.0', '192.168.1.1', 'eth0', 100)
            >>> print(route.pretty())
            '    192.168.1.0    255.255.255.0      192.168.1.1 100             eth0'
        """
        return f"{self.subnet:>16s} {self.netmask:>16s} {self.gateway:>16s} {self.metric:d} {self.interface:>16s}"
    
    def __str__(self) -> str:
        """
        String representation of the route.
        
        Returns:
            str: A human-readable string representation
        """
        return self.pretty()
    
    def __repr__(self) -> str:
        """
        Developer-friendly representation of the route.
        
        Returns:
            str: A string that could be used to recreate the object
        """
        return (f"Route(subnet={self.subnet!r}, netmask={self.netmask!r}, "
                f"gateway={self.gateway!r}, interface={self.interface!r}, "
                f"metric={self.metric!r})")
    
    def __eq__(self, other) -> bool:
        """
        Check equality with another Route object.
        
        Args:
            other: Another Route object to compare with
            
        Returns:
            bool: True if routes are equal, False otherwise
        """
        if not isinstance(other, Route):
            return False
        return (
            self.subnet == other.subnet and
            self.netmask == other.netmask and
            self.gateway == other.gateway and
            self.interface == other.interface and
            self.metric == other.metric
        )
    
    def __hash__(self) -> int:
        """
        Generate hash for the route (useful for sets and dicts).
        
        Returns:
            int: Hash value of the route
        """
        return hash((self.subnet, self.netmask, self.gateway, self.interface, self.metric))
    
    @property
    def is_ipv4(self) -> bool:
        """
        Check if this is an IPv4 route.
        
        Returns:
            bool: True if IPv4, False otherwise
        """
        try:
            ipaddress.IPv4Address(self.subnet)
            return True
        except ipaddress.AddressValueError:
            return False
    
    @property
    def is_ipv6(self) -> bool:
        """
        Check if this is an IPv6 route.
        
        Returns:
            bool: True if IPv6, False otherwise
        """
        try:
            ipaddress.IPv6Address(self.subnet)
            return True
        except ipaddress.AddressValueError:
            return False
    
    def to_dict(self) -> dict:
        """
        Convert the route to a dictionary.
        
        Returns:
            dict: Dictionary representation of the route
        """
        return {
            'subnet': self.subnet,
            'netmask': self.netmask,
            'gateway': self.gateway,
            'interface': self.interface,
            'metric': self.metric
        }
    
    @classmethod
    def from_dict(cls, data: dict) -> 'Route':
        """
        Create a Route instance from a dictionary.
        
        Args:
            data: Dictionary containing route data
            
        Returns:
            Route: A new Route instance
        """
        return cls(
            subnet=data['subnet'],
            netmask=data['netmask'],
            gateway=data['gateway'],
            interface=data.get('interface', ''),
            metric=data.get('metric', 0)
        )


# For backward compatibility with Ruby naming convention
class NetworkRoute(Route):
    """
    Alias for Route class for backward compatibility.
    
    This class is provided as a compatibility alias for code that may use
    the more explicit 'NetworkRoute' naming convention. It is functionally
    identical to the Route class.
    
    Usage:
        Both Route and NetworkRoute can be used interchangeably:
        
        >>> route1 = Route('192.168.1.0', '255.255.255.0', '192.168.1.1')
        >>> route2 = NetworkRoute('192.168.1.0', '255.255.255.0', '192.168.1.1')
        >>> route1 == route2
        True
    
    Note:
        For new code, prefer using Route directly as it is more concise.
    """
    pass
