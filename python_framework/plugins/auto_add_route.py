#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
Python Auto Add Route Plugin

This is a Python conversion of the Ruby auto_add_route.rb plugin.
Adds routes for any new subnets whenever a session opens.

Original Ruby version for Metasploit Framework.
Python conversion for Metasploit Framework Python migration.
"""

import logging
import re
from typing import Any, Dict

# Framework imports (these would be part of the Python MSF framework)
try:
    from msf.core.plugin import Plugin
    from msf.core.session_event import SessionEvent
    from msf.core.framework import Framework
    from rex.socket.switch_board import SwitchBoard
except ImportError:
    # Fallback for development/testing
    class Plugin:
        def __init__(self, framework: Any, opts: Dict[str, Any]):
            self.framework = framework
            self.opts = opts
            
    class SessionEvent:
        pass
        
    class Framework:
        def __init__(self):
            self.sessions = {}
            self.events = MockEvents()
            
    class SwitchBoard:
        @classmethod
        def instance(cls):
            return cls()
            
        def route_exists(self, subnet: str, netmask: str) -> bool:
            return False
            
        def add_route(self, subnet: str, netmask: str, session: Any) -> None:
            pass
            
    class MockEvents:
        def add_session_subscriber(self, subscriber):
            pass
            
        def remove_session_subscriber(self, subscriber):
            pass


class AutoAddRoute(Plugin, SessionEvent):
    """
    Python Auto Add Route Plugin
    
    Automatically adds routes for new subnets whenever a meterpreter session opens.
    This helps with network pivoting by automatically discovering and routing to
    internal networks accessible through compromised hosts.
    """
    
    def __init__(self, framework: Framework, opts: Dict[str, Any]):
        """
        Initialize the plugin
        
        Args:
            framework: The MSF framework instance
            opts: Plugin options
        """
        super().__init__(framework, opts)
        self.framework.events.add_session_subscriber(self)
        
    @property
    def name(self) -> str:
        """Plugin name"""
        return 'auto_add_route'
        
    @property
    def description(self) -> str:
        """Plugin description"""
        return 'Adds routes for any new subnets whenever a session opens'
        
    def on_session_open(self, session: Any) -> None:
        """
        Handle new session opening event
        
        Args:
            session: The newly opened session
        """
        # Only process meterpreter sessions
        if session.session_type != 'meterpreter':
            return
            
        try:
            # Load stdapi if not already loaded
            session.load_stdapi()
            
            # Get switch board instance for routing
            switch_board = SwitchBoard.instance()
            
            # Iterate through network configuration routes
            for route in session.net.config.routes:
                # Skip multicast and loopback interfaces
                if self._should_skip_route(route):
                    continue
                    
                # Add route if it doesn't already exist
                if not switch_board.route_exists(route.subnet, route.netmask):
                    logging.info(f"AutoAddRoute: Routing new subnet {route.subnet}/{route.netmask} through session {session.sid}")
                    switch_board.add_route(route.subnet, route.netmask, session)
                    
        except Exception as e:
            logging.error(f"AutoAddRoute: Error processing session {session.sid}: {e}")
            
    def _should_skip_route(self, route: Any) -> bool:
        """
        Determine if a route should be skipped
        
        Args:
            route: The route object to check
            
        Returns:
            True if the route should be skipped
        """
        # Skip multicast addresses (224.x.x.x)
        if re.match(r'^224\.', route.subnet):
            return True
            
        # Skip loopback addresses (127.x.x.x)
        if re.match(r'^127\.', route.subnet):
            return True
            
        # Skip default route
        if route.subnet == '0.0.0.0':
            return True
            
        # Skip host routes (single IP)
        if route.netmask == '255.255.255.255':
            return True
            
        return False
        
    def cleanup(self) -> None:
        """Clean up plugin resources"""
        self.framework.events.remove_session_subscriber(self)


# Plugin metadata for framework registration
PLUGIN_METADATA = {
    'name': 'Auto Add Route',
    'description': 'Adds routes for any new subnets whenever a session opens',
    'author': ['Metasploit Framework Team', 'Python conversion team'],
    'version': '1.0.0',
    'license': 'MSF_LICENSE',
    'type': 'session_plugin',
    'requirements': ['meterpreter'],
    'notes': {
        'stability': ['STABLE'],
        'reliability': ['REPEATABLE'],
        'side_effects': ['NETWORK_ROUTING']
    }
}


def create_plugin(framework: Framework, opts: Dict[str, Any] = None) -> AutoAddRoute:
    """
    Plugin factory function
    
    Args:
        framework: The MSF framework instance
        opts: Plugin options
        
    Returns:
        AutoAddRoute plugin instance
    """
    if opts is None:
        opts = {}
    return AutoAddRoute(framework, opts)


if __name__ == '__main__':
    # For testing/development
    logging.basicConfig(level=logging.INFO)
    
    # Mock objects for testing
    class MockRoute:
        def __init__(self, subnet: str, netmask: str):
            self.subnet = subnet
            self.netmask = netmask
            
    class MockNetConfig:
        def __init__(self):
            self.routes = [
                MockRoute('192.168.1.0', '255.255.255.0'),
                MockRoute('10.0.0.0', '255.0.0.0'),
                MockRoute('224.0.0.1', '255.255.255.255'),  # Should be skipped
                MockRoute('127.0.0.1', '255.255.255.255'),  # Should be skipped
            ]
            
    class MockNet:
        def __init__(self):
            self.config = MockNetConfig()
            
    class MockSession:
        def __init__(self, sid: int):
            self.sid = sid
            self.session_type = 'meterpreter'
            self.net = MockNet()
            
        def load_stdapi(self):
            print(f"Loading stdapi for session {self.sid}")
            
    class MockFramework:
        def __init__(self):
            self.sessions = {}
            self.events = MockEvents()
    
    # Test the plugin
    framework = MockFramework()
    plugin = create_plugin(framework)
    
    # Test session opening
    test_session = MockSession(1)
    plugin.on_session_open(test_session)
    
    print("\nPlugin created and tested successfully!")