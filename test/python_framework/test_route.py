#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
Unit tests for the Route class.

This test module validates the Python implementation of the Route class,
ensuring it maintains compatibility with the Ruby version while adding
Python-specific enhancements.
"""

import unittest
import ipaddress
from python_framework.net.route import Route, NetworkRoute


class TestRoute(unittest.TestCase):
    """Test cases for the Route class."""
    
    def test_init_with_string_addresses(self):
        """Test initialization with string IP addresses."""
        route = Route('192.168.1.0', '255.255.255.0', '192.168.1.1', 'eth0', 100)
        
        self.assertEqual(route.subnet, '192.168.1.0')
        self.assertEqual(route.netmask, '255.255.255.0')
        self.assertEqual(route.gateway, '192.168.1.1')
        self.assertEqual(route.interface, 'eth0')
        self.assertEqual(route.metric, 100)
    
    def test_init_with_bytes_ipv4(self):
        """Test initialization with IPv4 addresses as network byte order bytes."""
        # 192.168.1.0 in network byte order
        subnet_bytes = b'\xc0\xa8\x01\x00'
        # 255.255.255.0 in network byte order
        netmask_bytes = b'\xff\xff\xff\x00'
        # 192.168.1.1 in network byte order
        gateway_bytes = b'\xc0\xa8\x01\x01'
        
        route = Route(subnet_bytes, netmask_bytes, gateway_bytes, 'eth0', 10)
        
        self.assertEqual(route.subnet, '192.168.1.0')
        self.assertEqual(route.netmask, '255.255.255.0')
        self.assertEqual(route.gateway, '192.168.1.1')
        self.assertEqual(route.interface, 'eth0')
        self.assertEqual(route.metric, 10)
    
    def test_init_with_bytes_ipv6(self):
        """Test initialization with IPv6 addresses as network byte order bytes."""
        # 2001:db8::1 in network byte order
        subnet_bytes = b'\x20\x01\x0d\xb8\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00'
        # ffff:ffff:ffff:ffff:: netmask
        netmask_bytes = b'\xff\xff\xff\xff\xff\xff\xff\xff\x00\x00\x00\x00\x00\x00\x00\x00'
        # 2001:db8::1 gateway
        gateway_bytes = b'\x20\x01\x0d\xb8\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x01'
        
        route = Route(subnet_bytes, netmask_bytes, gateway_bytes, 'eth0', 5)
        
        self.assertEqual(route.subnet, '2001:db8::')
        self.assertEqual(route.netmask, 'ffff:ffff:ffff:ffff::')
        self.assertEqual(route.gateway, '2001:db8::1')
        self.assertEqual(route.interface, 'eth0')
        self.assertEqual(route.metric, 5)
    
    def test_init_with_default_interface_and_metric(self):
        """Test initialization with default interface and metric values."""
        route = Route('10.0.0.0', '255.0.0.0', '10.0.0.1')
        
        self.assertEqual(route.subnet, '10.0.0.0')
        self.assertEqual(route.netmask, '255.0.0.0')
        self.assertEqual(route.gateway, '10.0.0.1')
        self.assertEqual(route.interface, '')
        self.assertEqual(route.metric, 0)
    
    def test_pretty_format(self):
        """Test the pretty() method output format."""
        route = Route('192.168.1.0', '255.255.255.0', '192.168.1.1', 'eth0', 100)
        pretty_output = route.pretty()
        
        # Check that output contains all components
        self.assertIn('192.168.1.0', pretty_output)
        self.assertIn('255.255.255.0', pretty_output)
        self.assertIn('192.168.1.1', pretty_output)
        self.assertIn('100', pretty_output)
        self.assertIn('eth0', pretty_output)
        
        # Verify format is right-aligned with spaces
        parts = pretty_output.split()
        self.assertEqual(len(parts), 5)
    
    def test_str_representation(self):
        """Test string representation uses pretty format."""
        route = Route('10.0.0.0', '255.0.0.0', '10.0.0.1', 'wlan0', 50)
        str_output = str(route)
        pretty_output = route.pretty()
        
        self.assertEqual(str_output, pretty_output)
    
    def test_repr_representation(self):
        """Test repr() returns a recreatable representation."""
        route = Route('172.16.0.0', '255.255.0.0', '172.16.0.1', 'eth1', 20)
        repr_output = repr(route)
        
        self.assertIn('Route(', repr_output)
        self.assertIn("subnet='172.16.0.0'", repr_output)
        self.assertIn("netmask='255.255.0.0'", repr_output)
        self.assertIn("gateway='172.16.0.1'", repr_output)
        self.assertIn("interface='eth1'", repr_output)
        self.assertIn("metric=20", repr_output)
    
    def test_equality(self):
        """Test equality comparison between routes."""
        route1 = Route('192.168.1.0', '255.255.255.0', '192.168.1.1', 'eth0', 100)
        route2 = Route('192.168.1.0', '255.255.255.0', '192.168.1.1', 'eth0', 100)
        route3 = Route('192.168.2.0', '255.255.255.0', '192.168.2.1', 'eth0', 100)
        
        self.assertEqual(route1, route2)
        self.assertNotEqual(route1, route3)
        self.assertNotEqual(route1, "not a route")
    
    def test_hash(self):
        """Test that routes can be hashed and used in sets/dicts."""
        route1 = Route('192.168.1.0', '255.255.255.0', '192.168.1.1', 'eth0', 100)
        route2 = Route('192.168.1.0', '255.255.255.0', '192.168.1.1', 'eth0', 100)
        route3 = Route('192.168.2.0', '255.255.255.0', '192.168.2.1', 'eth0', 100)
        
        # Same routes should have same hash
        self.assertEqual(hash(route1), hash(route2))
        
        # Can be used in sets
        route_set = {route1, route2, route3}
        self.assertEqual(len(route_set), 2)  # route1 and route2 are duplicates
    
    def test_is_ipv4_property(self):
        """Test is_ipv4 property."""
        ipv4_route = Route('192.168.1.0', '255.255.255.0', '192.168.1.1')
        ipv6_route = Route('2001:db8::', 'ffff:ffff::', '2001:db8::1')
        
        self.assertTrue(ipv4_route.is_ipv4)
        self.assertFalse(ipv4_route.is_ipv6)
        
        self.assertTrue(ipv6_route.is_ipv6)
        self.assertFalse(ipv6_route.is_ipv4)
    
    def test_to_dict(self):
        """Test conversion to dictionary."""
        route = Route('192.168.1.0', '255.255.255.0', '192.168.1.1', 'eth0', 100)
        route_dict = route.to_dict()
        
        self.assertEqual(route_dict['subnet'], '192.168.1.0')
        self.assertEqual(route_dict['netmask'], '255.255.255.0')
        self.assertEqual(route_dict['gateway'], '192.168.1.1')
        self.assertEqual(route_dict['interface'], 'eth0')
        self.assertEqual(route_dict['metric'], 100)
    
    def test_from_dict(self):
        """Test creation from dictionary."""
        route_data = {
            'subnet': '10.0.0.0',
            'netmask': '255.0.0.0',
            'gateway': '10.0.0.1',
            'interface': 'wlan0',
            'metric': 50
        }
        
        route = Route.from_dict(route_data)
        
        self.assertEqual(route.subnet, '10.0.0.0')
        self.assertEqual(route.netmask, '255.0.0.0')
        self.assertEqual(route.gateway, '10.0.0.1')
        self.assertEqual(route.interface, 'wlan0')
        self.assertEqual(route.metric, 50)
    
    def test_from_dict_with_defaults(self):
        """Test from_dict with missing optional fields."""
        route_data = {
            'subnet': '172.16.0.0',
            'netmask': '255.255.0.0',
            'gateway': '172.16.0.1'
        }
        
        route = Route.from_dict(route_data)
        
        self.assertEqual(route.subnet, '172.16.0.0')
        self.assertEqual(route.interface, '')
        self.assertEqual(route.metric, 0)
    
    def test_invalid_string_address(self):
        """Test that invalid string addresses raise ValueError."""
        with self.assertRaises(ValueError):
            Route('invalid.ip.address', '255.255.255.0', '192.168.1.1')
        
        with self.assertRaises(ValueError):
            Route('192.168.1.0', 'invalid.netmask', '192.168.1.1')
    
    def test_invalid_bytes_length(self):
        """Test that invalid byte lengths raise ValueError."""
        with self.assertRaises(ValueError):
            # Only 3 bytes instead of 4 for IPv4
            Route(b'\xc0\xa8\x01', b'\xff\xff\xff\x00', b'\xc0\xa8\x01\x01')
    
    def test_invalid_type(self):
        """Test that invalid types raise TypeError."""
        with self.assertRaises(TypeError):
            Route(12345, '255.255.255.0', '192.168.1.1')
    
    def test_network_route_alias(self):
        """Test NetworkRoute alias works correctly."""
        route = NetworkRoute('192.168.1.0', '255.255.255.0', '192.168.1.1')
        
        self.assertIsInstance(route, Route)
        self.assertIsInstance(route, NetworkRoute)
        self.assertEqual(route.subnet, '192.168.1.0')
    
    def test_route_with_loopback(self):
        """Test route with loopback addresses."""
        route = Route('127.0.0.0', '255.0.0.0', '127.0.0.1', 'lo', 0)
        
        self.assertEqual(route.subnet, '127.0.0.0')
        self.assertEqual(route.gateway, '127.0.0.1')
        self.assertTrue(route.is_ipv4)
    
    def test_route_with_zero_address(self):
        """Test route with 0.0.0.0 (default route)."""
        route = Route('0.0.0.0', '0.0.0.0', '192.168.1.1', 'eth0', 0)
        
        self.assertEqual(route.subnet, '0.0.0.0')
        self.assertEqual(route.netmask, '0.0.0.0')
        self.assertEqual(route.gateway, '192.168.1.1')


class TestRouteEdgeCases(unittest.TestCase):
    """Test edge cases and special scenarios."""
    
    def test_multiple_routes_in_collection(self):
        """Test managing multiple routes in a collection."""
        routes = [
            Route('192.168.1.0', '255.255.255.0', '192.168.1.1', 'eth0', 100),
            Route('10.0.0.0', '255.0.0.0', '10.0.0.1', 'eth1', 50),
            Route('172.16.0.0', '255.255.0.0', '172.16.0.1', 'wlan0', 75)
        ]
        
        self.assertEqual(len(routes), 3)
        
        # Test sorting by metric
        sorted_routes = sorted(routes, key=lambda r: r.metric)
        self.assertEqual(sorted_routes[0].metric, 50)
        self.assertEqual(sorted_routes[2].metric, 100)
    
    def test_ipv6_link_local(self):
        """Test IPv6 link-local addresses."""
        route = Route('fe80::', 'ffff:ffff:ffff:ffff::', 'fe80::1', 'eth0', 0)
        
        self.assertTrue(route.is_ipv6)
        self.assertIn('fe80::', route.subnet)
    
    def test_route_comparison_with_none(self):
        """Test route comparison with None."""
        route = Route('192.168.1.0', '255.255.255.0', '192.168.1.1')
        
        self.assertNotEqual(route, None)
        self.assertFalse(route == None)


if __name__ == '__main__':
    unittest.main()
