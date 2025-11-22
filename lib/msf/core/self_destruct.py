#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
Self-Destruct Semi-Malware Framework

This module provides time-limited, self-removing malware capabilities for
realistic penetration testing. Designed to automatically deactivate and
remove itself after a specified time period.

This addresses the gap where malicious actors can plant persistent malware
but testers cannot, making testing more realistic while maintaining ethics.

Author: P4x-ng
License: MSF_LICENSE
"""

import os
import sys
import json
import time
import atexit
import signal
import hashlib
import platform
from datetime import datetime, timedelta
from typing import Optional, Dict, Callable


class SelfDestructMalware:
    """
    Self-destructing malware framework with automatic cleanup.
    
    Features:
    - Time-based deactivation
    - Automatic self-removal attempt
    - Fallback to logging if removal fails
    - Clear uninstall instructions
    - Cross-platform support (Windows, Linux, macOS)
    """
    
    def __init__(self, 
                 lifetime_hours: int = 24,
                 payload_callback: Optional[Callable] = None,
                 config_file: str = None):
        """
        Initialize self-destruct malware.
        
        Args:
            lifetime_hours (int): Hours until auto-deactivation (default: 24)
            payload_callback (callable): Function to execute as payload
            config_file (str): Path to configuration file
        """
        self.lifetime_hours = lifetime_hours
        self.payload_callback = payload_callback
        self.config_file = config_file or self._get_default_config_path()
        
        self.start_time = None
        self.expiry_time = None
        self.active = False
        self.removal_attempted = False
        
        # Register cleanup handlers
        atexit.register(self.cleanup)
        signal.signal(signal.SIGTERM, self._signal_handler)
        signal.signal(signal.SIGINT, self._signal_handler)
        
        self._load_or_create_config()
    
    def _get_default_config_path(self) -> str:
        """Get default configuration file path based on platform."""
        if platform.system() == 'Windows':
            return os.path.join(os.environ.get('TEMP', 'C:\\Temp'), 
                              '.msf_semiware.json')
        else:
            return os.path.join('/tmp', '.msf_semiware.json')
    
    def _load_or_create_config(self):
        """Load existing config or create new one."""
        if os.path.exists(self.config_file):
            try:
                with open(self.config_file, 'r') as f:
                    config = json.load(f)
                    self.start_time = datetime.fromisoformat(config['start_time'])
                    self.expiry_time = datetime.fromisoformat(config['expiry_time'])
                    self.active = config.get('active', False)
            except Exception as e:
                print(f"Warning: Could not load config: {e}")
                self._create_new_config()
        else:
            self._create_new_config()
    
    def _create_new_config(self):
        """Create new configuration."""
        self.start_time = datetime.now()
        self.expiry_time = self.start_time + timedelta(hours=self.lifetime_hours)
        self.active = True
        self._save_config()
    
    def _save_config(self):
        """Save configuration to disk."""
        try:
            config = {
                'start_time': self.start_time.isoformat(),
                'expiry_time': self.expiry_time.isoformat(),
                'active': self.active,
                'lifetime_hours': self.lifetime_hours,
                'platform': platform.system(),
                'install_path': os.path.abspath(__file__)
            }
            
            with open(self.config_file, 'w') as f:
                json.dump(config, f, indent=2)
        
        except Exception as e:
            print(f"Warning: Could not save config: {e}")
    
    def _signal_handler(self, signum, frame):
        """Handle termination signals."""
        print("\nReceived termination signal, cleaning up...")
        self.cleanup()
        sys.exit(0)
    
    def is_expired(self) -> bool:
        """Check if the malware has expired."""
        if not self.start_time or not self.expiry_time:
            return True
        
        return datetime.now() >= self.expiry_time
    
    def time_remaining(self) -> timedelta:
        """Get time remaining until expiration."""
        if self.is_expired():
            return timedelta(0)
        
        return self.expiry_time - datetime.now()
    
    def run(self) -> Dict:
        """
        Run the semi-malware payload.
        
        Returns:
            dict: Execution result
        """
        result = {
            'success': False,
            'expired': False,
            'time_remaining': None
        }
        
        # Check if expired
        if self.is_expired():
            print("[*] Semi-malware has expired. Initiating self-destruct...")
            result['expired'] = True
            self.deactivate()
            return result
        
        # Show time remaining
        remaining = self.time_remaining()
        result['time_remaining'] = str(remaining)
        print(f"[*] Semi-malware active. Time remaining: {remaining}")
        
        # Execute payload if provided
        if self.payload_callback and self.active:
            try:
                result['payload_result'] = self.payload_callback()
                result['success'] = True
            except Exception as e:
                result['error'] = str(e)
                print(f"[!] Payload execution error: {e}")
        
        # Check expiration again after execution
        if self.is_expired():
            self.deactivate()
        
        return result
    
    def deactivate(self):
        """Deactivate the malware and attempt removal."""
        if not self.active:
            return
        
        print("[*] Deactivating semi-malware...")
        self.active = False
        self._save_config()
        
        # Attempt self-removal
        self.attempt_removal()
    
    def attempt_removal(self) -> bool:
        """
        Attempt to remove the malware from the system.
        
        Returns:
            bool: True if removal succeeded
        """
        if self.removal_attempted:
            return False
        
        self.removal_attempted = True
        
        print("[*] Attempting self-removal...")
        
        # Try to remove configuration file
        try:
            if os.path.exists(self.config_file):
                os.remove(self.config_file)
                print(f"[+] Removed config file: {self.config_file}")
        except Exception as e:
            print(f"[-] Could not remove config file: {e}")
        
        # Try to remove executable/script
        try:
            script_path = os.path.abspath(__file__)
            
            if os.path.exists(script_path):
                # On Windows, can't delete running script, schedule for deletion
                if platform.system() == 'Windows':
                    self._schedule_windows_deletion(script_path)
                else:
                    # On Unix, can delete while running
                    os.remove(script_path)
                    print(f"[+] Removed script: {script_path}")
                    return True
        
        except Exception as e:
            print(f"[-] Could not remove script: {e}")
            self._emit_removal_logs()
            return False
        
        return True
    
    def _schedule_windows_deletion(self, path: str):
        """Schedule file deletion on Windows after reboot."""
        try:
            try:
                import winreg
            except ImportError:
                print(f"[-] winreg not available, cannot schedule deletion")
                self._emit_removal_logs()
                return
            
            # Add to RunOnce for deletion
            key = winreg.OpenKey(winreg.HKEY_CURRENT_USER,
                                r'Software\Microsoft\Windows\CurrentVersion\RunOnce',
                                0, winreg.KEY_SET_VALUE)
            
            value_name = f'MSFCleanup{hashlib.md5(path.encode()).hexdigest()[:8]}'
            value_data = f'cmd.exe /c del /f /q "{path}"'
            
            winreg.SetValueEx(key, value_name, 0, winreg.REG_SZ, value_data)
            winreg.CloseKey(key)
            
            print(f"[+] Scheduled deletion on next boot: {path}")
        
        except Exception as e:
            print(f"[-] Could not schedule deletion: {e}")
            self._emit_removal_logs()
    
    def _emit_removal_logs(self):
        """
        Emit logs with removal instructions when automatic removal fails.
        This is the fallback mechanism.
        """
        print("\n" + "="*70)
        print("METASPLOIT SEMI-MALWARE REMOVAL REQUIRED")
        print("="*70)
        print("\n[!] Automatic removal failed. Manual removal required.")
        print(f"\n[*] Installation Details:")
        print(f"    - Config file: {self.config_file}")
        print(f"    - Script path: {os.path.abspath(__file__)}")
        print(f"    - Platform: {platform.system()}")
        print(f"    - Start time: {self.start_time}")
        print(f"    - Expiry time: {self.expiry_time}")
        
        print(f"\n[*] Manual Removal Instructions:")
        
        if platform.system() == 'Windows':
            print(f"    1. Delete config file:")
            print(f"       del \"{self.config_file}\"")
            print(f"    2. Delete script:")
            print(f"       del \"{os.path.abspath(__file__)}\"")
            print(f"    3. Check registry Run keys:")
            print(f"       HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run")
            print(f"       HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\RunOnce")
        
        else:
            print(f"    1. Delete config file:")
            print(f"       rm -f {self.config_file}")
            print(f"    2. Delete script:")
            print(f"       rm -f {os.path.abspath(__file__)}")
            print(f"    3. Check crontab:")
            print(f"       crontab -l | grep -v '{os.path.basename(__file__)}' | crontab -")
            print(f"    4. Check autostart:")
            print(f"       rm -f ~/.config/autostart/*.desktop")
        
        print("\n" + "="*70)
        
        # Also write to system logs
        self._write_system_log()
    
    def _write_system_log(self):
        """Write removal instructions to system log."""
        log_message = f"""
METASPLOIT SEMI-MALWARE REMOVAL REQUIRED

Installation Details:
- Config file: {self.config_file}
- Script path: {os.path.abspath(__file__)}
- Platform: {platform.system()}
- Start time: {self.start_time}
- Expiry time: {self.expiry_time}

This is a time-limited testing tool that has expired.
Please remove the files listed above.

For assistance, see: https://docs.metasploit.com/docs/development/
"""
        
        try:
            if platform.system() == 'Windows':
                # Write to Windows Event Log
                try:
                    import win32evtlogutil
                    import win32evtlog
                    
                    win32evtlogutil.ReportEvent(
                        "Metasploit",
                        1,  # Event ID
                        eventType=win32evtlog.EVENTLOG_WARNING_TYPE,
                        strings=[log_message]
                    )
                except (ImportError, Exception):
                    # Fallback to file if pywin32 not available or error occurs
                    log_file = os.path.join(os.environ.get('TEMP', 'C:\\Temp'),
                                          'msf_removal_required.log')
                    with open(log_file, 'w') as f:
                        f.write(log_message)
                    print(f"[*] Log written to: {log_file}")
            
            else:
                # Write to syslog on Unix
                import syslog
                syslog.openlog('metasploit-semiware')
                syslog.syslog(syslog.LOG_WARNING, log_message)
                syslog.closelog()
                
                # Also write to file
                log_file = '/tmp/msf_removal_required.log'
                with open(log_file, 'w') as f:
                    f.write(log_message)
                print(f"[*] Log written to: {log_file}")
        
        except Exception as e:
            print(f"[-] Could not write to system log: {e}")
    
    def cleanup(self):
        """Final cleanup on exit."""
        if self.is_expired() and not self.removal_attempted:
            self.attempt_removal()


def create_self_destruct_payload(lifetime_hours: int = 24,
                                 payload_function: Optional[Callable] = None) -> str:
    """
    Create a standalone self-destruct payload script.
    
    Args:
        lifetime_hours (int): Hours until self-destruct
        payload_function (callable): Payload to execute
        
    Returns:
        str: Path to created payload script
    """
    script_template = f'''#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Self-Destruct Semi-Malware Payload
Generated by Metasploit PyNative

This payload will automatically deactivate and remove itself after {lifetime_hours} hours.
"""

import sys
import os

# Add this script's directory to path
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from lib.msf.core.self_destruct import SelfDestructMalware


def payload():
    """Your payload code here."""
    # PAYLOAD_CODE_PLACEHOLDER
    pass


if __name__ == '__main__':
    malware = SelfDestructMalware(lifetime_hours={lifetime_hours},
                                   payload_callback=payload)
    
    result = malware.run()
    
    if result.get('expired'):
        print("[*] Payload expired and removed")
        sys.exit(0)
    
    # Keep running if needed
    while not malware.is_expired():
        import time
        time.sleep(60)  # Check every minute
        
        if malware.is_expired():
            malware.deactivate()
            break
'''
    
    # Write script to temp file
    import tempfile
    fd, path = tempfile.mkstemp(suffix='.py', prefix='msf_semiware_')
    
    with os.fdopen(fd, 'w') as f:
        f.write(script_template)
    
    os.chmod(path, 0o755)
    
    return path


if __name__ == '__main__':
    # Test the self-destruct malware
    def test_payload():
        print("[*] Test payload executing...")
        return {'test': 'success'}
    
    # Create with 1 hour lifetime for testing
    malware = SelfDestructMalware(lifetime_hours=1, 
                                   payload_callback=test_payload)
    
    print(f"[*] Malware created with {malware.lifetime_hours}h lifetime")
    print(f"[*] Expiry time: {malware.expiry_time}")
    
    result = malware.run()
    print(f"[*] Result: {result}")
    
    # Manually trigger deactivation for testing
    malware.deactivate()
