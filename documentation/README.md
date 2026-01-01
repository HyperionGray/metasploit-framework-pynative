# Metasploit Framework Documentation

This directory contains comprehensive documentation for the Metasploit Framework, including both classic Ruby and Python-native features.

## Quick Navigation

### Getting Started
- **[Main Documentation Site](https://docs.metasploit.com/)** - Official Metasploit documentation
- **[Python Migration README](../PYTHON_MIGRATION_README.md)** - Guide for the Python-native framework
- **[Python Quickstart](../PYTHON_QUICKSTART.md)** - Quick start for Python modules

### Python-Native Features
- **[Exploit Writing Guide](EXPLOIT_WRITING_GUIDE.md)** - Comprehensive guide to writing exploits in Python
- **[PF Integration Guide](PF_INTEGRATION_GUIDE.md)** - Using Pwntools, Radare2, and other tools
- **[Module Categorization](MODULE_CATEGORIZATION.md)** - Understanding legacy vs. active modules
- **[Shell Catcher & C2 Guide](SHELL_CATCHER_C2_GUIDE.md)** - Modern C2 and shell handling
- **[Shell Catcher Quickstart](SHELL_CATCHER_C2_QUICKSTART.md)** - Quick reference for C2 tools

### Development Resources
- **[Developer's Guide PDF](developers_guide.pdf)** - Classic Metasploit development guide
- **[API Documentation](https://rapid7.github.io/metasploit-framework/api)** - Generated API docs

### Transpiler Tools
- **[Transpilers Directory](../transpilers/README.md)** - Ruby↔Python conversion tools
- **[Ruby to Python Converter](../transpilers/ruby2py/README.md)** - Convert Ruby modules to Python
- **[Python to Ruby Transpiler](../transpilers/py2ruby/README.md)** - Convert Python modules to Ruby

## Directory Structure

```
documentation/
├── README.md                       # This file
├── EXPLOIT_WRITING_GUIDE.md        # Comprehensive exploit writing guide
├── MODULE_CATEGORIZATION.md        # Module organization and legacy info
├── PF_INTEGRATION_GUIDE.md         # Pwntools, Radare2, GDB integration
├── SHELL_CATCHER_C2_GUIDE.md       # C2 frameworks and shell catchers
├── SHELL_CATCHER_C2_QUICKSTART.md  # Quick C2 reference
├── developers_guide.pdf            # Classic developer guide
├── cli/                            # Command-line interface docs
├── integrations/                   # Integration documentation
└── modules/                        # Module-specific documentation
```

## Python-Native Metasploit

This fork has been enhanced with Python-native capabilities:

### Key Features
- ✅ **7,456+ Python modules** converted from Ruby
- ✅ **Python framework core** with type hints and modern patterns
- ✅ **Bidirectional transpilers** for Ruby↔Python conversion
- ✅ **Modern tooling** including Pwntools, Radare2, GDB integration
- ✅ **Virtualenv-like activation** with `source msfrc`

### Quick Start Commands

```bash
# Activate MSF environment (like Python virtualenv) - RECOMMENDED
source msfrc

# Use MSF commands from your shell
msf_console    # Python-enhanced console
msf_venom      # Payload generator
msf_exploit    # Quick exploit launcher
msf_search     # Search modules
msf_info       # Show environment info

# Run a Python exploit module
python3 modules/exploits/linux/http/example.py --help

# Convert Ruby module to Python
python3 ruby2py/convert.py old_module.rb

# Convert Python module to Ruby
python3 ruby2py/py2ruby/transpiler.py new_module.py -o output.rb

# Deactivate when done
msf_deactivate
```

## Writing Exploits

### Python-Native Approach (Recommended for new modules)

```python
from python_framework.core.exploit import RemoteExploit, ExploitInfo
from python_framework.helpers.http_client import HttpExploitMixin

class MyExploit(RemoteExploit, HttpExploitMixin):
    def __init__(self):
        info = ExploitInfo(
            name="My Exploit",
            description="Exploit description",
            author=["Your Name"],
            references=["CVE-2024-XXXXX"]
        )
        super().__init__(info)
    
    def exploit(self) -> ExploitResult:
        # Your exploitation code
        pass
```

See [EXPLOIT_WRITING_GUIDE.md](EXPLOIT_WRITING_GUIDE.md) for complete examples.

### Classic Ruby Approach (For legacy compatibility)

Classic Ruby module development is documented at:
- https://docs.metasploit.com/docs/development/developing-modules/
- https://docs.metasploit.com/docs/development/get-started/

## Integration with Modern Tools

### Pwntools Integration
Use industry-standard exploitation tools alongside Metasploit:

```python
from pwn import *
context.log_level = 'debug'

# Your Pwntools code
```

See [PF_INTEGRATION_GUIDE.md](PF_INTEGRATION_GUIDE.md) for details.

### C2 Frameworks
Integrate with modern Command & Control frameworks:

- **Sliver** - Professional Go-based C2
- **Havoc** - Modern C2 with GUI teamserver
- **pwncat-cs** - Advanced shell handler
- **Villain** - Web-based shell manager

See [SHELL_CATCHER_C2_GUIDE.md](SHELL_CATCHER_C2_GUIDE.md) for setup.

## Metasploit Community

Metasploit is actively supported by a community of hundreds of contributors and thousands of users world-wide.

### Key Resources
- **[GitHub Discussions](https://github.com/rapid7/metasploit-framework/discussions)** - Community Q&A
- **[Metasploit Slack](https://metasploit.com/slack)** - Real-time chat
- **[GitHub Issues](https://github.com/rapid7/metasploit-framework/issues)** - Bug reports
- **[Official Docs](https://docs.metasploit.com/)** - Comprehensive documentation

### Topics Covered in Official Docs
- [Evading Antivirus](https://docs.metasploit.com/docs/using-metasploit/intermediate/evading-anti-virus.html)
- [How Payloads Work](https://docs.metasploit.com/docs/using-metasploit/basics/how-payloads-work.html)
- [Datastore Options](https://docs.metasploit.com/docs/development/developing-modules/module-metadata/how-to-use-datastore-options.html)
- [Browser Exploits with BES](https://docs.metasploit.com/docs/development/developing-modules/libraries/http/how-to-write-a-browser-exploit-using-browserexploitserver.html)
- [Writing a Bruteforcer](https://docs.metasploit.com/docs/development/developing-modules/libraries/how-to-use-msf-auxiliary-authbrute-to-write-a-bruteforcer.html)

...and many, many more.

## API Documentation

### Python Framework API
The Python-native framework includes comprehensive type hints and docstrings:

```bash
# Generate Python API docs
python3 -m pydoc -b

# Or browse the code
ls python_framework/
```

### Ruby Framework API
Generate YARD documentation for Ruby components:

```bash
rake yard
```

Or visit https://rapid7.github.io/metasploit-framework/api for a recently generated online version.

## Contributing to Documentation

We welcome documentation contributions! Here's how:

### For Python Documentation
1. Add docstrings following Google style guide
2. Include type hints for all functions
3. Provide usage examples
4. Submit a pull request

### For Ruby Documentation
1. Write YARD-compatible comments ([yardoc.org](http://yardoc.org/))
2. Follow existing documentation patterns
3. Test with `rake yard`
4. Submit a [Pull Request](https://github.com/rapid7/metasploit-framework/pulls)

## Finding More Help

- **Configuration**: See `../config/` for Python config files
- **Examples**: Browse `../examples/` for working examples
- **Modules**: Check `../modules/` for exploit examples
- **Tools**: Explore `../tools/` for helper utilities
- **Transpilers**: Visit `../transpilers/` for conversion tools

## License

All documentation is part of the Metasploit Framework and released under the same BSD-style license.

