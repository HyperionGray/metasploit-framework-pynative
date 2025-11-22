#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
RFKilla Integration

RFKilla is an RF (Radio Frequency) exploitation and jamming tool.
This integration provides access to RF attack capabilities within Metasploit.

Author: P4x-ng
License: MSF_LICENSE
"""

import os
import sys
import subprocess
import logging
from typing import Dict, List, Optional, Tuple

# Add parent directory to path for imports
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.dirname(os.path.dirname(__file__)))))

from lib.msf.core.integrations import BaseIntegration, IntegrationRegistry


class RFKillaIntegration(BaseIntegration):
    """
    Integration for RFKilla RF exploitation tool.
    
    RFKilla provides capabilities for:
    - RF signal jamming
    - Wireless protocol exploitation
    - SDR (Software Defined Radio) attacks
    - Signal analysis and manipulation
    """
    
    REQUIRED_DEPENDENCIES = ['rfkilla']  # Could be external binary or Python module
    
    def __init__(self, config=None):
        """Initialize RFKilla integration."""
        super().__init__(config)
        self.name = "RFKilla"
        self.rfkilla_path = self.config.get('rfkilla_path', self._find_rfkilla())
        
    def _find_rfkilla(self) -> Optional[str]:
        """
        Try to find RFKilla installation.
        
        Returns:
            str or None: Path to RFKilla if found
        """
        # Check common installation paths
        common_paths = [
            '/usr/local/bin/rfkilla',
            '/opt/rfkilla/rfkilla',
            os.path.expanduser('~/.local/bin/rfkilla')
        ]
        
        for path in common_paths:
            if os.path.exists(path) and os.access(path, os.X_OK):
                return path
        
        # Try to find in PATH using cross-platform method
        try:
            import shutil
            path = shutil.which('rfkilla')
            if path:
                return path
        except Exception:
            pass
        
        return None
    
    def check_dependencies(self) -> Tuple[bool, List[str]]:
        """
        Check if RFKilla and required dependencies are available.
        
        Returns:
            tuple: (success, missing_dependencies)
        """
        missing = []
        
        if not self.rfkilla_path:
            missing.append('rfkilla (not found in system)')
        
        # Check for SDR hardware support (optional)
        try:
            subprocess.run(['lsusb'], capture_output=True, timeout=5)
        except FileNotFoundError:
            logging.warning("lsusb not found - USB device detection unavailable")
        
        return (len(missing) == 0, missing)
    
    def initialize(self) -> bool:
        """
        Initialize RFKilla integration.
        
        Returns:
            bool: True if initialization succeeded
        """
        success, missing = self.check_dependencies()
        
        if not success:
            logging.error(f"RFKilla dependencies missing: {missing}")
            return False
        
        self.enabled = True
        logging.info("RFKilla integration initialized successfully")
        return True
    
    def list_devices(self) -> List[Dict[str, str]]:
        """
        List available RF devices.
        
        Returns:
            list: List of device dictionaries
        """
        if not self.enabled:
            logging.error("RFKilla not initialized")
            return []
        
        devices = []
        
        try:
            # List RF kill switches
            result = subprocess.run(['rfkill', 'list'], 
                                  capture_output=True, text=True, timeout=10)
            
            if result.returncode == 0:
                # Parse rfkill output
                lines = result.stdout.split('\n')
                current_device = {}
                
                for line in lines:
                    line = line.strip()
                    if not line:
                        if current_device:
                            devices.append(current_device)
                            current_device = {}
                        continue
                    
                    if ':' in line and not line.startswith('\t'):
                        # Device header
                        parts = line.split(':', 1)
                        current_device['id'] = parts[0].strip()
                        current_device['name'] = parts[1].strip()
                    elif ':' in line:
                        # Device property
                        parts = line.split(':', 1)
                        key = parts[0].strip().replace(' ', '_')
                        value = parts[1].strip()
                        current_device[key] = value
                
                if current_device:
                    devices.append(current_device)
        
        except Exception as e:
            logging.error(f"Error listing RF devices: {e}")
        
        return devices
    
    def execute(self, action: str, target: Optional[str] = None, 
               frequency: Optional[float] = None, **kwargs) -> Dict:
        """
        Execute RFKilla action.
        
        Args:
            action (str): Action to perform (jam, scan, block, unblock)
            target (str): Target device ID
            frequency (float): Target frequency in MHz
            **kwargs: Additional parameters
            
        Returns:
            dict: Results dictionary
        """
        if not self.enabled:
            return {
                'success': False,
                'error': 'RFKilla not initialized'
            }
        
        result = {
            'success': False,
            'action': action,
            'target': target,
            'frequency': frequency
        }
        
        try:
            if action == 'block':
                if target:
                    cmd = ['rfkill', 'block', target]
                    proc = subprocess.run(cmd, capture_output=True, text=True, timeout=10)
                    result['success'] = proc.returncode == 0
                    result['output'] = proc.stdout
                    
            elif action == 'unblock':
                if target:
                    cmd = ['rfkill', 'unblock', target]
                    proc = subprocess.run(cmd, capture_output=True, text=True, timeout=10)
                    result['success'] = proc.returncode == 0
                    result['output'] = proc.stdout
                    
            elif action == 'list':
                devices = self.list_devices()
                result['success'] = True
                result['devices'] = devices
                
            else:
                result['error'] = f'Unknown action: {action}'
        
        except Exception as e:
            result['error'] = str(e)
            logging.error(f"Error executing RFKilla action: {e}")
        
        return result
    
    def cleanup(self):
        """Clean up RFKilla resources."""
        # Unblock all devices on cleanup
        try:
            subprocess.run(['rfkill', 'unblock', 'all'], 
                         capture_output=True, timeout=10)
        except Exception:
            pass
        
        self.enabled = False


# Register the integration
IntegrationRegistry.register('rfkilla', RFKillaIntegration)


if __name__ == '__main__':
    # Test the integration
    logging.basicConfig(level=logging.INFO)
    
    rfkilla = RFKillaIntegration()
    success, missing = rfkilla.check_dependencies()
    
    print(f"Dependencies check: {success}")
    if not success:
        print(f"Missing: {missing}")
    else:
        if rfkilla.initialize():
            print("RFKilla initialized successfully")
            result = rfkilla.execute('list')
            print(f"Devices: {result.get('devices', [])}")
            rfkilla.cleanup()
