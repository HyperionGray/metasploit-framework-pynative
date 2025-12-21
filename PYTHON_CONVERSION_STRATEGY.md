# Python Conversion Strategy - Round 4

## Overview

This document outlines the strategy for converting Metasploit Framework from Ruby to Python, creating a fully Python-native penetration testing framework.

## Conversion Principles

### Timeline-Based Approach

**Post-2020 Modules (Priority 1)**
- All modules with `DisclosureDate >= 2020-01-01` should be converted to Python
- These represent current, actively-used exploits and tools
- Will use the native Python module framework

**Pre-2020 Modules (Legacy)**
- Modules with `DisclosureDate < 2020-01-01` move to `modules_legacy/`
- Maintained in Ruby for backward compatibility
- Can be selectively converted as needed

### Framework Components

**Core Framework (lib/)**
- Convert Rex library to Python (networking, protocol handling, utilities)
- Convert Msf::Core classes to Python equivalents
- Maintain compatibility layer for legacy modules

**Module Types**
- **Exploits**: Convert to Python with native HTTP/socket libraries
- **Auxiliary**: Scanner, fuzzer, and utility modules in Python
- **Post**: Post-exploitation modules in Python
- **Payloads**: Generate payloads using Python templating
- **Encoders**: Python-based payload encoding
- **Evasion**: Anti-detection techniques in Python

## Directory Structure

```
metasploit-framework-pynative/
├── lib/
│   ├── msf/           # Python framework core
│   ├── rex/           # Python protocol/network library
│   └── metasploit/    # Python module interface
├── modules/
│   ├── exploits/      # Post-2020 exploits (Python)
│   ├── auxiliary/     # Post-2020 auxiliary (Python)
│   ├── post/          # Post-2020 post-exploit (Python)
│   ├── payloads/      # Payload generators (Python)
│   └── encoders/      # Encoders (Python)
├── modules_legacy/    # Pre-2020 modules (Ruby)
│   ├── exploits/
│   ├── auxiliary/
│   └── post/
├── tools/             # Conversion and utility tools
└── docs/              # Documentation
```

## Python Module Framework

### Module Structure

All Python modules follow this template:

```python
#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import logging
from metasploit import module

metadata = {
    'name': 'Module Name',
    'description': '''
        Module description here.
    ''',
    'authors': ['Author Name'],
    'date': 'YYYY-MM-DD',
    'license': 'MSF_LICENSE',
    'references': [
        {'type': 'cve', 'ref': '2024-XXXXX'},
        {'type': 'url', 'ref': 'https://example.com'}
    ],
    'type': 'remote_exploit',  # or single_scanner, post, etc.
    'targets': [
        {'platform': 'linux', 'arch': 'x64'}
    ],
    'options': {
        'rhost': {'type': 'address', 'description': 'Target', 'required': True},
        'rport': {'type': 'port', 'description': 'Port', 'required': True, 'default': 80}
    },
    'notes': {
        'stability': ['CRASH_SAFE'],
        'reliability': ['REPEATABLE_SESSION'],
        'side_effects': ['IOC_IN_LOGS']
    }
}

def run(args):
    module.LogHandler.setup(msg_prefix='{} - '.format(args['rhost']))
    
    # Module logic here
    logging.info('Exploiting target...')
    
    # Return success/failure
    return True

if __name__ == '__main__':
    module.run(metadata, run)
```

### Framework Helpers

**HTTP Client** (`lib/msf/http_client.py`)
```python
from metasploit.http import HTTPClient

client = HTTPClient(args['rhost'], args['rport'])
response = client.get('/path', headers={'User-Agent': 'MSF'})
```

**TCP Socket** (`lib/rex/socket.py`)
```python
from rex.socket import TCPSocket

sock = TCPSocket(args['rhost'], args['rport'])
sock.send(b'data')
response = sock.recv(1024)
sock.close()
```

**Payload Generation** (`lib/msf/payload.py`)
```python
from msf.payload import generate_payload

payload = generate_payload(
    payload_type='cmd/unix/reverse_bash',
    lhost=args['lhost'],
    lport=args['lport']
)
```

## Conversion Process

### Phase 1: Core Framework (In Progress)
- [x] Basic module interface (`lib/msf/core/modules/external/python/metasploit/`)
- [x] Rex utilities (SMB, deserialization helpers)
- [ ] HTTP client library
- [ ] TCP/UDP socket wrappers
- [ ] Payload generation system
- [ ] Session management

### Phase 2: Post-2020 Exploits
- [ ] Identify all exploits with DisclosureDate >= 2020
- [ ] Convert top 10 most-used exploits
- [ ] Convert browser exploits
- [ ] Convert web application exploits
- [ ] Convert network service exploits

### Phase 3: Auxiliary Modules
- [ ] Convert scanners (port, vulnerability, auth)
- [ ] Convert fuzzers
- [ ] Convert DOS modules
- [ ] Convert information gathering tools

### Phase 4: Post-Exploitation
- [ ] Convert Meterpreter scripts to Python
- [ ] Convert privilege escalation modules
- [ ] Convert credential harvesting
- [ ] Convert persistence mechanisms

### Phase 5: Legacy Migration
- [ ] Move pre-2020 modules to modules_legacy/
- [ ] Create compatibility shim
- [ ] Document legacy module usage
- [ ] Selective conversion of high-value legacy modules

## Testing Strategy

### Unit Tests
```python
# test/modules/test_exploit_name.py
import unittest
from modules.exploits.category import exploit_name

class TestExploitName(unittest.TestCase):
    def test_check_vulnerable(self):
        # Test vulnerability check
        pass
    
    def test_exploit_success(self):
        # Test successful exploitation
        pass
```

### Integration Tests
- Test module loading via msfconsole
- Test option parsing and validation
- Test payload generation and delivery
- Test session establishment

### Compatibility Tests
- Ensure Python modules work with Ruby framework
- Test module metadata parsing
- Verify logging and reporting functions

## Migration Tools

### Automatic Conversion Tool (`tools/ruby_to_python.py`)
- Parse Ruby module structure
- Generate Python module template
- Convert common patterns (pack/unpack, regex, etc.)
- Flag manual conversion requirements

### Module Linter (`tools/python_module_lint.py`)
- Validate Python module structure
- Check metadata completeness
- Verify option definitions
- Test imports and dependencies

### Testing Framework (`tools/test_converted_module.py`)
- Run basic sanity checks on converted modules
- Compare behavior with Ruby original
- Generate test reports

## Ruby → Python Common Patterns

| Ruby | Python | Notes |
|------|--------|-------|
| `attr_accessor :var` | `@property` | Property decorators |
| `#{variable}` | `f"{variable}"` | F-strings |
| `:symbol` | `"symbol"` | Strings instead of symbols |
| `[1].pack('n')` | `struct.pack('>H', 1)` | Binary packing |
| `str.unpack('nn')` | `struct.unpack('>HH', str)` | Binary unpacking |
| `send_request_cgi` | `requests.get/post` | HTTP requests |
| `Rex::Socket::Tcp.create` | `socket.socket()` | TCP sockets |
| `payload.encoded` | `generate_payload()` | Payload generation |
| `fail_with` | `raise MSFException` | Error handling |
| `register_options` | `metadata['options']` | Module options |

## Code Quality Standards

### Python Style
- Follow PEP 8 style guide
- Use type hints where appropriate
- Document all public functions
- Maximum line length: 120 characters

### Security
- Validate all user inputs
- Sanitize data before execution
- Use parameterized queries for databases
- Avoid command injection vulnerabilities
- No hardcoded credentials

### Performance
- Use async/await for I/O operations
- Minimize external dependencies
- Cache expensive computations
- Profile critical code paths

## Documentation Requirements

### Module Documentation
Each module must include:
- Purpose and functionality
- Requirements and dependencies
- Target platforms and versions
- Usage examples
- Known limitations
- References and credits

### API Documentation
- Docstrings for all public functions
- Parameter descriptions with types
- Return value specifications
- Exception documentation
- Usage examples

## Current Status

### Completed (Round 1-3)
- ✅ Python module interface framework
- ✅ 48+ utility and helper modules converted
- ✅ Basic Rex protocol utilities (SMB, serialization)
- ✅ Meterpreter scripts (20+ scripts)
- ✅ Development tools and module analysis tools
- ✅ Binary analysis integration (Radare2, LLVM)
- ✅ Example modules and documentation

### Round 4 Goals
- 🎯 Convert post-2020 exploit modules to Python
- 🎯 Create comprehensive framework helpers for exploits
- 🎯 Establish legacy module structure
- 🎯 Complete HTTP/TCP client libraries
- 🎯 Implement payload generation system
- 🎯 Create automated conversion tools

### Target Modules for Round 4
Post-2020 exploits identified for conversion:
1. `multi/php/ignition_laravel_debug_rce` (2021-01-13)
2. `multi/misc/apache_activemq_rce_cve_2023_46604` (2023-10-27)
3. `multi/php/jorani_path_trav` (2023-01-06)
4. `multi/fileformat/gitlens_local_config_exec` (2023-11-14)
5. `multi/misc/cups_ipp_remote_code_execution` (2024-09-26)
6. `multi/misc/calibre_exec` (2024-07-31)
7. `multi/browser/chrome_cve_2021_21220_v8_insufficient_validation` (2021-04-13)
8. `multi/kubernetes/exec` (2021-10-01)
9. `multi/misc/nomad_exec` (2021-05-17)
10. `multi/misc/vscode_ipynb_remote_dev_exec` (2022-11-22)

## Contributing

When converting modules:
1. Follow the module template structure
2. Test thoroughly before submitting
3. Document any deviations from Ruby original
4. Include usage examples
5. Update this document with progress

## References

- [Metasploit Framework](https://github.com/rapid7/metasploit-framework)
- [Python Module Development](https://docs.metasploit.com/docs/development/developing-modules/external-modules/Python-Modules.html)
- [PYTHON_TRANSLATIONS.md](PYTHON_TRANSLATIONS.md) - Previously converted modules
- [PYTHON_QUICKSTART.md](PYTHON_QUICKSTART.md) - Quick start guide
