#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
MSF JSON-RPC Web Service - Python Implementation

This is the Python-native implementation of the Metasploit JSON-RPC API.
Replaces the Ruby msf-json-rpc.ru rackup file.

Start using:
    python3 msf-json-rpc.py
    # or with gunicorn/waitress:
    gunicorn -b localhost:8081 msf-json-rpc:app
    waitress-serve --host=localhost --port=8081 msf-json-rpc:app
"""

import os
import sys
from pathlib import Path

try:
    from flask import Flask, jsonify
except ImportError:
    print("Error: Flask is required. Install with: pip3 install flask", file=sys.stderr)
    sys.exit(1)

# Setup MSF environment
MSF_ROOT = Path(__file__).resolve().parent
sys.path.insert(0, str(MSF_ROOT / "lib"))
sys.path.insert(0, str(MSF_ROOT / "python_framework"))
sys.path.insert(0, str(MSF_ROOT))

if os.environ.get('MSF_LOCAL_LIB'):
    sys.path.insert(0, os.environ['MSF_LOCAL_LIB'])

# Set environment variables
os.environ['MSF_ROOT'] = str(MSF_ROOT)
os.environ['MSF_PYTHON_MODE'] = '1'
app = Flask(__name__)
@app.route('/api/v1/health', methods=['GET'])
def health():
    """Health check endpoint for warmup verification."""
    return jsonify({'data': {'status': 'UP'}})

@app.route('/api/v1/version', methods=['GET'])
def version():
    """Version information endpoint."""
    return jsonify({
        'data': {
            'version': 'PyNative-1.0',
            'implementation': 'Python',
            'status': 'operational'
        }
    })

@app.route('/')
def root():
    """Root endpoint with API information."""
    return jsonify({
        'service': 'Metasploit JSON-RPC API',
        'implementation': 'Python-Native',
        'endpoints': [
            '/api/v1/health',
            '/api/v1/version'
        ],
        'note': 'Full RPC implementation pending Python MSF framework completion'
    })

# Placeholder for future RPC endpoints
@app.route('/api/v1/<path:endpoint>', methods=['GET', 'POST', 'PUT', 'DELETE'])
def api_placeholder(endpoint):
    """Placeholder for future RPC endpoints."""
    return jsonify({
        'error': 'Endpoint not yet implemented',
        'endpoint': endpoint,
        'message': 'Full JSON-RPC functionality is under development in Python'
    }), 501


def main():
    """Run the development server."""
    import argparse
    
    parser = argparse.ArgumentParser(
        description='Metasploit JSON-RPC Web Service (Python)'
    )
    parser.add_argument('--host', default='localhost',
                       help='Host to bind to (default: localhost)')
    parser.add_argument('--port', type=int, default=8081,
                       help='Port to bind to (default: 8081)')
    parser.add_argument('--debug', action='store_true',
                       help='Enable debug mode')
    
    args = parser.parse_args()
    
    print("=" * 70)
    print("  Metasploit JSON-RPC Web Service - Python-Native")
    print("=" * 70)
    print()
    print(f"  Binding to: {args.host}:{args.port}")
    print(f"  Debug mode: {'Enabled' if args.debug else 'Disabled'}")
    print()
    print("  Available endpoints:")
    print("    GET  /api/v1/health   - Health check")
    print("    GET  /api/v1/version  - Version info")
    print()
    print("  For production deployment, use gunicorn or waitress:")
    print(f"    gunicorn -b {args.host}:{args.port} msf-json-rpc:app")
    print(f"    waitress-serve --host={args.host} --port={args.port} msf-json-rpc:app")
    print()
    print("=" * 70)
    print()
    
    app.run(host=args.host, port=args.port, debug=args.debug)


if __name__ == '__main__':
    main()
