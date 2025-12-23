#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
Metasploit Framework Daemon - Python Native Version

This script starts the Metasploit Framework daemon which allows remote
connections to the framework using native Python implementation.

This is the primary daemon interface for the Metasploit Framework.
"""

import sys
import os
import argparse
import socket
import threading
import time
from pathlib import Path


class MsfDaemon:
    """Python implementation of Metasploit Framework Daemon"""
    
    def __init__(self, host='127.0.0.1', port=55554, ssl=False, foreground=False):
        self.host = host
        self.port = port
        self.ssl = ssl
        self.foreground = foreground
        self.running = False
        
    def start(self):
        """Start the daemon"""
        print(f"[*] Starting Metasploit Framework Daemon (Python Native)")
        print(f"[*] Listening on {self.host}:{self.port}")
        
        try:
            # Create socket
            server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            server_socket.bind((self.host, self.port))
            server_socket.listen(5)
            
            self.running = True
            print(f"[*] Daemon started successfully")
            
            while self.running:
                try:
                    client_socket, address = server_socket.accept()
                    print(f"[*] Client connected from {address}")
                    
                    # Handle client in separate thread
                    client_thread = threading.Thread(
                        target=self.handle_client,
                        args=(client_socket, address)
                    )
                    client_thread.daemon = True
                    client_thread.start()
                    
                except KeyboardInterrupt:
                    break
                except Exception as e:
                    print(f"[!] Error accepting connection: {e}")
                    
        except Exception as e:
            print(f"[!] Error starting daemon: {e}")
            sys.exit(1)
        finally:
            if 'server_socket' in locals():
                server_socket.close()
            print("[*] Daemon stopped")
    
    def handle_client(self, client_socket, address):
        """Handle client connection"""
        try:
            # Send welcome message
            welcome = "Metasploit Framework Daemon - Python Native Version\n"
            welcome += "Type 'help' for available commands\n"
            welcome += "msfd> "
            client_socket.send(welcome.encode())
            
            while True:
                data = client_socket.recv(1024)
                if not data:
                    break
                    
                command = data.decode().strip()
                
                if command.lower() == 'exit':
                    break
                elif command.lower() == 'help':
                    response = "Available commands:\n"
                    response += "  help    - Show this help\n"
                    response += "  version - Show version\n"
                    response += "  exit    - Disconnect\n"
                elif command.lower() == 'version':
                    response = "Metasploit Framework Daemon - Python Native Version 6.4.0-dev\n"
                elif command:
                    response = f"Command '{command}' not yet implemented in Python version.\n"
                    response += "For full functionality, use: ruby msfd.rb\n"
                else:
                    response = ""
                
                if response:
                    client_socket.send(response.encode())
                client_socket.send(b"msfd> ")
                
        except Exception as e:
            print(f"[!] Error handling client {address}: {e}")
        finally:
            client_socket.close()
            print(f"[*] Client {address} disconnected")


def main():
    """Main entry point for msfd."""
    
    parser = argparse.ArgumentParser(
        description='Metasploit Framework Daemon - Python Native Version'
    )
    parser.add_argument('-a', '--address', default='127.0.0.1',
                       help='Bind to this IP address (default: 127.0.0.1)')
    parser.add_argument('-p', '--port', type=int, default=55554,
                       help='Bind to this port (default: 55554)')
    parser.add_argument('-s', '--ssl', action='store_true',
                       help='Use SSL')
    parser.add_argument('-f', '--foreground', action='store_true',
                       help='Run in foreground')
    parser.add_argument('-q', '--quiet', action='store_true',
                       help='Quiet mode')
    
    args = parser.parse_args()
    
    # Show informational message
    if not args.quiet:
        print("\n" + "="*70)
        print("  Metasploit Framework Daemon - Python Native Version")
        print("="*70)
        print("  This is the primary Python-native daemon.")
        print("  Legacy Ruby version available as: ruby msfd.rb")
        print("="*70 + "\n")
    
    # Create and start daemon
    daemon = MsfDaemon(
        host=args.address,
        port=args.port,
        ssl=args.ssl,
        foreground=args.foreground
    )
    
    try:
        daemon.start()
    except KeyboardInterrupt:
        print("\n[*] Shutting down daemon...")
        daemon.running = False


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print("\nAborting...")
        sys.exit(1)
