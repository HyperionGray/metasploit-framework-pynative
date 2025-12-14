#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
Example usage of the Python Route class.

This example demonstrates how to use the Route class for network routing
management, including creating routes, displaying them, and working with
both IPv4 and IPv6 addresses.
"""

import sys
sys.path.insert(0, '/home/runner/work/metasploit-framework-pynative/metasploit-framework-pynative')

from python_framework.net.route import Route


def main():
    """Demonstrate Route class functionality."""
    
    print("=" * 70)
    print("Python Route Class Example - Network Routing Management")
    print("=" * 70)
    print()
    
    # Example 1: Creating IPv4 routes with string addresses
    print("1. Creating IPv4 routes with string addresses:")
    print("-" * 70)
    
    route1 = Route('192.168.1.0', '255.255.255.0', '192.168.1.1', 'eth0', 100)
    route2 = Route('10.0.0.0', '255.0.0.0', '10.0.0.1', 'eth1', 50)
    route3 = Route('172.16.0.0', '255.255.0.0', '172.16.0.1', 'wlan0', 75)
    
    print("Route 1:")
    print(f"  {route1.pretty()}")
    print(f"  Is IPv4: {route1.is_ipv4}")
    print()
    
    print("Route 2:")
    print(f"  {route2.pretty()}")
    print(f"  Subnet: {route2.subnet}, Gateway: {route2.gateway}")
    print()
    
    print("Route 3:")
    print(f"  {route3.pretty()}")
    print(f"  Interface: {route3.interface}, Metric: {route3.metric}")
    print()
    
    # Example 2: Creating routes from network byte order bytes
    print("2. Creating routes from network byte order bytes:")
    print("-" * 70)
    
    # Simulating data received from Meterpreter (network byte order)
    subnet_bytes = b'\xc0\xa8\x02\x00'    # 192.168.2.0
    netmask_bytes = b'\xff\xff\xff\x00'   # 255.255.255.0
    gateway_bytes = b'\xc0\xa8\x02\x01'   # 192.168.2.1
    
    route_from_bytes = Route(subnet_bytes, netmask_bytes, gateway_bytes, 'eth2', 10)
    print("Route from bytes (as from Meterpreter):")
    print(f"  {route_from_bytes.pretty()}")
    print()
    
    # Example 3: IPv6 routes
    print("3. IPv6 route support:")
    print("-" * 70)
    
    ipv6_route = Route('2001:db8::', 'ffff:ffff::', '2001:db8::1', 'eth0', 5)
    print("IPv6 Route:")
    print(f"  {ipv6_route.pretty()}")
    print(f"  Is IPv6: {ipv6_route.is_ipv6}")
    print()
    
    # Example 4: Managing routes in collections
    print("4. Managing routes in a routing table:")
    print("-" * 70)
    
    routing_table = [route1, route2, route3, route_from_bytes]
    
    print("Active Routing Table")
    print("=" * 70)
    print(f"{'Subnet':<18} {'Netmask':<18} {'Gateway':<18} {'Metric':<8} {'Interface'}")
    print("-" * 70)
    
    for route in routing_table:
        print(route.pretty())
    print()
    
    # Example 5: Sorting routes by metric
    print("5. Sorting routes by metric (priority):")
    print("-" * 70)
    
    sorted_routes = sorted(routing_table, key=lambda r: r.metric)
    
    print("Routes sorted by metric (lowest to highest):")
    for route in sorted_routes:
        print(f"  Metric {route.metric:3d}: {route.subnet} via {route.gateway} ({route.interface})")
    print()
    
    # Example 6: Route equality and hashing
    print("6. Route equality and deduplication:")
    print("-" * 70)
    
    duplicate_route = Route('192.168.1.0', '255.255.255.0', '192.168.1.1', 'eth0', 100)
    
    print(f"route1 == duplicate_route: {route1 == duplicate_route}")
    print(f"route1 is duplicate_route: {route1 is duplicate_route}")
    print()
    
    # Using set to remove duplicates
    all_routes = [route1, route2, duplicate_route, route3]
    unique_routes = list(set(all_routes))
    
    print(f"Original list has {len(all_routes)} routes")
    print(f"After deduplication: {len(unique_routes)} unique routes")
    print()
    
    # Example 7: Serialization to/from dictionary
    print("7. Serialization to/from dictionary:")
    print("-" * 70)
    
    route_dict = route1.to_dict()
    print("Route as dictionary:")
    for key, value in route_dict.items():
        print(f"  {key}: {value}")
    print()
    
    restored_route = Route.from_dict(route_dict)
    print(f"Restored route: {restored_route.pretty()}")
    print(f"Restored == Original: {restored_route == route1}")
    print()
    
    # Example 8: Default route (0.0.0.0)
    print("8. Default route:")
    print("-" * 70)
    
    default_route = Route('0.0.0.0', '0.0.0.0', '192.168.1.1', 'eth0', 0)
    print("Default route (0.0.0.0/0.0.0.0):")
    print(f"  {default_route.pretty()}")
    print()
    
    print("=" * 70)
    print("Example completed successfully!")
    print("=" * 70)


if __name__ == '__main__':
    main()
