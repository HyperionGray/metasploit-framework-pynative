# Network Module - Python Framework

This module provides network-related classes and utilities for the Metasploit Python Framework.

## Overview

The `net` module contains Python implementations of network configuration and routing classes that were originally implemented in Ruby. These classes are used by Meterpreter and other framework components to manage network information.

## Components

### Route (`route.py`)

Represents a logical network route with support for both IPv4 and IPv6 addresses.

**Features:**
- IPv4 and IPv6 address support
- Network byte order conversion (compatible with Ruby's `IPAddr.new_ntoh`)
- Pretty formatting for display
- Dictionary serialization/deserialization
- Hash support for use in sets and dictionaries

**Example Usage:**

```python
from python_framework.net.route import Route

# Create a route with string addresses
route = Route('192.168.1.0', '255.255.255.0', '192.168.1.1', 'eth0', 100)

# Create a route from network byte order bytes (as received from Meterpreter)
subnet_bytes = b'\xc0\xa8\x01\x00'  # 192.168.1.0
netmask_bytes = b'\xff\xff\xff\x00'  # 255.255.255.0
gateway_bytes = b'\xc0\xa8\x01\x01'  # 192.168.1.1
route = Route(subnet_bytes, netmask_bytes, gateway_bytes, 'eth0', 10)

# Display route
print(route.pretty())
# Output:     192.168.1.0    255.255.255.0      192.168.1.1 10             eth0

# Check IP version
if route.is_ipv4:
    print("This is an IPv4 route")

# Convert to/from dictionary
route_dict = route.to_dict()
route2 = Route.from_dict(route_dict)

# IPv6 example
ipv6_route = Route('2001:db8::', 'ffff:ffff::', '2001:db8::1', 'eth0', 5)
print(ipv6_route.pretty())
```

## Ruby Compatibility

This module maintains compatibility with the Ruby Rex::Post::Meterpreter::Extensions::Stdapi::Net module:

| Ruby Class | Python Class | Status |
|------------|--------------|--------|
| `Rex::Post::Meterpreter::Extensions::Stdapi::Net::Route` | `python_framework.net.Route` | ✅ Complete |
| `Rex::Post::Meterpreter::Extensions::Stdapi::Net::Interface` | `python_framework.net.Interface` | 🔄 Planned |
| `Rex::Post::Meterpreter::Extensions::Stdapi::Net::Arp` | `python_framework.net.Arp` | 🔄 Planned |
| `Rex::Post::Meterpreter::Extensions::Stdapi::Net::Config` | `python_framework.net.Config` | 🔄 Planned |
| `Rex::Post::Meterpreter::Extensions::Stdapi::Net::Netstat` | `python_framework.net.Netstat` | 🔄 Planned |

## Testing

Tests are located in `test/python_framework/test_route.py`.

Run tests with:

```bash
cd /home/runner/work/metasploit-framework-pynative/metasploit-framework-pynative
PYTHONPATH=. python3 -m unittest test.python_framework.test_route -v
```

## Migration Notes

The Python implementation provides several enhancements over the Ruby version:

1. **Type Hints**: Full type annotations for better IDE support and type checking
2. **Properties**: `is_ipv4` and `is_ipv6` properties for convenient IP version checking
3. **Serialization**: Built-in `to_dict()` and `from_dict()` methods for easy serialization
4. **Hash Support**: Routes can be used in sets and as dictionary keys
5. **Better Error Messages**: More descriptive error messages with context

## Future Enhancements

Planned additions:
- CIDR notation support for easier subnet specification
- Route validation methods
- Network overlap detection
- Integration with Python's `ipaddress.IPv4Network` and `IPv6Network`
