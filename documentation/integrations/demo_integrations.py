#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
Comprehensive Integration Demo

This script demonstrates how to use all the new integrations together
in a realistic penetration testing scenario.

Author: P4x-ng
License: MSF_LICENSE
"""

import sys
import os
import time

# Add to path - go up two directories to reach the root
root_dir = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
sys.path.insert(0, root_dir)

from lib.msf.core.integrations import IntegrationRegistry
from lib.msf.core.integrations.rfkilla import RFKillaIntegration
from lib.msf.core.integrations.phoenixboot import PhoenixBootIntegration
from lib.msf.core.integrations.chrompwn import ChromPwnPanelIntegration
from lib.msf.core.self_destruct import SelfDestructMalware
from lib.msf.core.advanced_meterpreter import StealthMeterpreter


def demo_rfkilla():
    """Demonstrate RFKilla integration."""
    print("\n" + "="*70)
    print("DEMO 1: RF Jamming with RFKilla")
    print("="*70)
    
    rfkilla = RFKillaIntegration()
    
    success, missing = rfkilla.check_dependencies()
    if not success:
        print(f"[!] RFKilla not available: {missing}")
        print("[*] Skipping RF demo (requires Linux with rfkill)")
        return
    
    if rfkilla.initialize():
        print("[+] RFKilla initialized")
        
        # List devices
        result = rfkilla.execute('list')
        if result['success']:
            devices = result.get('devices', [])
            print(f"[*] Found {len(devices)} RF devices:")
            for device in devices:
                print(f"    - {device.get('name', 'Unknown')}: {device.get('id', 'N/A')}")
        
        rfkilla.cleanup()
        print("[+] RFKilla demo complete")


def demo_phoenixboot():
    """Demonstrate PhoenixBoot integration."""
    print("\n" + "="*70)
    print("DEMO 2: Persistence with PhoenixBoot")
    print("="*70)
    
    phoenixboot = PhoenixBootIntegration()
    
    if phoenixboot.initialize():
        print("[+] PhoenixBoot initialized")
        
        # Note: Not actually adding persistence in demo
        print("[*] PhoenixBoot can add persistence via:")
        print("    - cron (Linux/macOS)")
        print("    - systemd (Linux with root)")
        print("    - registry (Windows)")
        print("    - startup folder (All platforms)")
        
        # List protected processes
        result = phoenixboot.execute('list_protected')
        if result['success']:
            protected = result.get('protected', [])
            print(f"[*] Protected processes: {len(protected)}")
        
        phoenixboot.cleanup()
        print("[+] PhoenixBoot demo complete")


def demo_chrompwn():
    """Demonstrate ChromPwnPanel integration."""
    print("\n" + "="*70)
    print("DEMO 3: Browser Exploitation with ChromPwnPanel")
    print("="*70)
    
    config = {'host': '0.0.0.0', 'port': 8888, 'verbose': False}
    panel = ChromPwnPanelIntegration(config)
    
    success, missing = panel.check_dependencies()
    if not success:
        print(f"[!] ChromPwnPanel not available: {missing}")
        print("[*] Port may be in use, trying different port...")
        config['port'] = 8889
        panel = ChromPwnPanelIntegration(config)
        success, missing = panel.check_dependencies()
        if not success:
            print("[*] Skipping ChromPwn demo")
            return
    
    if panel.initialize():
        print("[+] ChromPwnPanel initialized")
        
        # Start server
        result = panel.execute('start')
        if result['success']:
            print(f"[+] Server started on port {config['port']}")
            print("[*] Victims would connect to: http://localhost:{config['port']}/")
            print("[*] Running for 3 seconds...")
            
            time.sleep(3)
            
            # Check victims
            result = panel.execute('list_victims')
            print(f"[*] Victims connected: {len(result.get('victims', []))}")
            
            # Stop server
            panel.execute('stop')
            print("[+] Server stopped")
        
        panel.cleanup()
        print("[+] ChromPwnPanel demo complete")


def demo_self_destruct():
    """Demonstrate Self-Destruct Semi-Malware."""
    print("\n" + "="*70)
    print("DEMO 4: Self-Destruct Semi-Malware")
    print("="*70)
    
    def demo_payload():
        print("    [Payload] Executing simulated malicious activity...")
        return {'status': 'executed'}
    
    # Create malware with 1 hour lifetime
    malware = SelfDestructMalware(
        lifetime_hours=1,
        payload_callback=demo_payload
    )
    
    print(f"[+] Created semi-malware with {malware.lifetime_hours}h lifetime")
    print(f"[*] Expiry time: {malware.expiry_time}")
    print(f"[*] Time remaining: {malware.time_remaining()}")
    
    # Run payload
    print("[*] Executing payload...")
    result = malware.run()
    
    if result['success']:
        print("[+] Payload executed successfully")
    
    print("[*] Semi-malware features:")
    print("    - Automatic deactivation after time limit")
    print("    - Self-removal attempt on expiration")
    print("    - Fallback logging if removal fails")
    print("    - Clear uninstall instructions")
    
    print("[+] Self-destruct demo complete")


def demo_advanced_meterpreter():
    """Demonstrate Advanced Meterpreter."""
    print("\n" + "="*70)
    print("DEMO 5: Advanced Stealth Meterpreter")
    print("="*70)
    
    meterpreter = StealthMeterpreter()
    meterpreter.start()
    
    print("[+] Stealth meterpreter started")
    print("[*] Network behavior baseline established")
    
    # Queue data for exfiltration
    print("[*] Queueing data for exfiltration...")
    meterpreter.queue_exfiltration(b"Sensitive data item 1", priority=3)
    meterpreter.queue_exfiltration(b"Critical data item" * 100, priority=5)
    meterpreter.queue_exfiltration(b"Low priority item", priority=1)
    
    # Exfiltrate using adaptive strategy
    print("[*] Analyzing network patterns and exfiltrating...")
    result = meterpreter.exfiltrate_data()
    
    print(f"[+] Exfiltration complete:")
    print(f"    - Strategy: {result.get('strategy', 'N/A')}")
    print(f"    - Bytes sent: {result.get('bytes_sent', 0)}")
    print(f"    - Items sent: {result.get('items_sent', 0)}")
    print(f"    - Queue remaining: {result.get('remaining_queue', 0)}")
    print(f"    - Next exfil in: {result.get('next_delay', 0)}s")
    
    # Show obfuscation
    print("[*] Code obfuscation demonstration...")
    sample = "import os; os.system('echo Hello')"
    obfuscated = meterpreter.generate_obfuscated_payload(sample)
    print(f"    - Original size: {len(sample)} bytes")
    print(f"    - Obfuscated size: {len(obfuscated)} bytes")
    print(f"    - Ratio: {len(obfuscated)/len(sample):.1f}x")
    
    meterpreter.stop()
    print("[+] Advanced meterpreter demo complete")


def demo_integration_registry():
    """Demonstrate Integration Registry."""
    print("\n" + "="*70)
    print("DEMO 6: Integration Registry")
    print("="*70)
    
    # List all registered integrations
    integrations = IntegrationRegistry.list_all()
    print(f"[*] Registered integrations: {len(integrations)}")
    for name in integrations:
        print(f"    - {name}")
    
    # Get a specific integration
    if 'rfkilla' in integrations:
        RFKillaClass = IntegrationRegistry.get('rfkilla')
        print(f"[+] Retrieved RFKilla class: {RFKillaClass.__name__}")
    
    print("[+] Registry demo complete")


def main():
    """Run all demos."""
    print("="*70)
    print("METASPLOIT PYNATIVE - ADVANCED INTEGRATIONS DEMO")
    print("="*70)
    print("\nThis demo showcases all the new unique features in PyMetasploit:")
    print("1. RFKilla - RF exploitation")
    print("2. PhoenixBoot - Persistence framework")
    print("3. ChromPwnPanel - Browser exploitation")
    print("4. Self-Destruct - Time-limited malware")
    print("5. Advanced Meterpreter - Stealth techniques")
    print("6. Integration Registry - Framework management")
    
    input("\nPress Enter to continue...")
    
    # Run demos
    demo_rfkilla()
    demo_phoenixboot()
    demo_chrompwn()
    demo_self_destruct()
    demo_advanced_meterpreter()
    demo_integration_registry()
    
    print("\n" + "="*70)
    print("DEMO COMPLETE")
    print("="*70)
    print("\nAll integrations demonstrated successfully!")
    print("\nFor more information:")
    print("- README: lib/msf/core/integrations/README.md")
    print("- Binary Analysis: documentation/integrations/BINARY_ANALYSIS_TOOLS.md")
    print("\nThese features make PyMetasploit unique and more powerful than")
    print("standard Metasploit, providing modern capabilities for realistic")
    print("penetration testing.")


if __name__ == '__main__':
    try:
        main()
    except KeyboardInterrupt:
        print("\n\n[*] Demo interrupted by user")
    except Exception as e:
        print(f"\n[!] Error during demo: {e}")
        import traceback
        traceback.print_exc()
