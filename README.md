# Metasploit Framework

The Metasploit Framework is an open-source tool released under a BSD-style license. For detailed licensing information, refer to the `COPYING` file.

## Latest Version
Access the latest version of Metasploit from the [Nightly Installers](https://docs.metasploit.com/docs/using-metasploit/getting-started/nightly-installers.html) page.

## Documentation
Comprehensive documentation, including usage guides, is available at [Metasploit Docs](https://docs.metasploit.com/).

## Development Environment
To set up a development environment, visit the [Development Setup Guide](https://docs.metasploit.com/docs/development/get-started/setting-up-a-metasploit-development-environment.html).

## Bug and Feature Requests
Submit bugs and feature requests via the [GitHub Issues](https://github.com/rapid7/metasploit-framework/issues) tracker. New submissions can be made through the [MSF-BUGv1 form](https://github.com/rapid7/metasploit-framework/issues/new/choose).

## API Documentation
For information on writing modules, refer to the [API Documentation](https://docs.metasploit.com/api/).

## Support and Communication
For questions and suggestions, you can:

- Join our [GitHub Discussions](https://github.com/rapid7/metasploit-framework/discussions) for community support and general questions
- Join the [Metasploit Slack](https://join.slack.com/t/metasploit/shared_invite/zt-30i688it0-mJsFGT44IMtdeZi1DraamQ) for real-time chat
- Submit [GitHub Issues](https://github.com/rapid7/metasploit-framework/issues) for bug reports and feature requests
- Follow [@metasploit](https://x.com/metasploit) on X or [@metasploit@infosec.exchange](https://infosec.exchange/@metasploit) on Mastodon for updates

**Note:** Some community members may still use IRC channels and the metasploit-hackers mailing list, though the primary support channels are now GitHub Discussions and Slack.

## Python-Native Framework (Round 4)

This fork is actively converting Metasploit Framework to Python, creating a fully Python-native penetration testing platform:

- **Post-2020 Modules**: Being converted to Python (`modules/`)
- **Pre-2020 Modules**: Maintained in Ruby for compatibility (`modules_legacy/`)
- **Python Framework**: Native HTTP clients, socket wrappers, and module interfaces
- **Conversion Tools**: Automated Ruby-to-Python conversion assistance

See [PYTHON_CONVERSION_STRATEGY.md](PYTHON_CONVERSION_STRATEGY.md) for the complete conversion plan and progress.

Quick start with Python modules:
```bash
# View conversion strategy and progress
cat PYTHON_CONVERSION_STRATEGY.md

# Run Python module example
python3 modules/exploits/multi/http/generic_rce_example_2024.py

# Analyze modules for legacy migration
python3 tools/legacy_module_migrator.py -s

# Convert a Ruby module to Python template
python3 tools/ruby_to_python_converter.py modules/exploits/path/to/module.rb
```

See also:
- [PYTHON_TRANSLATIONS.md](PYTHON_TRANSLATIONS.md) - List of 48+ converted modules
- [PYTHON_QUICKSTART.md](PYTHON_QUICKSTART.md) - Python module quick start guide
- [modules_legacy/README.md](modules_legacy/README.md) - Legacy module documentation

## Binary Analysis with Radare2

This fork includes advanced binary analysis capabilities with Radare2 integration:

- **GDB-like Commands**: Intuitive interface to Radare2 using familiar GDB syntax
- **LLDB Integration**: Dynamic debugging support for runtime analysis
- **Binary Instrumentation**: AFL-style coverage tracking and code path analysis  
- **In-Memory Fuzzing**: High-speed fuzzing with stack manipulation

See [RADARE2_QUICKSTART.md](RADARE2_QUICKSTART.md) for installation and usage guide.

Quick start:
```bash
# Install dependencies
pip3 install r2pipe

# Launch interactive debugger
python3 tools/binary_analysis/r2gdb.py /path/to/binary
```

## Installing Metasploit

### Recommended Installation

We recommend installation with the [official Metasploit installers](https://docs.metasploit.com/docs/using-metasploit/getting-started/nightly-installers.html#installing-metasploit-on-linux--macos) on Linux or macOS. Metasploit is also pre-installed with Kali.

For a manual setup, consult the [Dev Environment Setup](https://docs.metasploit.com/docs/development/get-started/setting-up-a-metasploit-development-environment.html) guide.

## Using Metasploit

To get started with Metasploit:

1. **Start `msfconsole`:** This is the primary interface for interacting with Metasploit.
2. **Explore Resources:** 
   - Visit the [Using Metasploit](https://docs.metasploit.com/docs/using-metasploit/getting-started/index.html) section of the documentation.

## PF Framework Integration

This fork embraces modern exploitation tools and techniques. Write exploits as Python tasks with full access to:

- **Pwntools**: Industry-standard exploitation library
- **Radare2**: Advanced binary analysis and reversing
- **GDB/GEF/pwndbg**: Interactive debugging with automation
- **AFL++/libFuzzer**: Coverage-guided fuzzing with sanitizers
- **Ghidra**: NSA's reverse engineering platform

**Quick Start:**
```bash
# See example PF task
python3 examples/pf_task_example.py --help

# Set target via environment variables (simpler than MSF's 'set' commands)
export TARGET_HOST=192.168.1.100
export TARGET_PORT=9999
python3 examples/pf_task_example.py --mode exploit
```

**Documentation:**
- [PF Integration Guide](documentation/PF_INTEGRATION_GUIDE.md) - Write exploits as PF tasks
- [Exploit Writing Guide](documentation/EXPLOIT_WRITING_GUIDE.md) - Comprehensive exploitation tutorial
- [Module Categorization](documentation/MODULE_CATEGORIZATION.md) - Understanding legacy vs. active modules

## Modern Shell Catchers and C2 Frameworks

This fork integrates professional-grade shell handling and C2 capabilities that scale well for red team operations:

### Shell Catchers
- **pwncat-cs** - Advanced shell handler with automatic privilege escalation, persistence, and post-exploitation modules
- **Villain** - Modern web-based UI for managing multiple shells at scale

### C2 Frameworks
- **Sliver** - Professional Go-based C2 with mTLS, WireGuard, HTTP(S), and DNS protocols
- **Havoc** - Modern C2 with GUI teamserver, sleep obfuscation, and indirect syscalls for evasion

**Quick Start:**
```bash
# Catch shells with pwncat-cs (auto privilege escalation)
use auxiliary/server/pwncat_listener
set LHOST 0.0.0.0
set LPORT 4444
run

# Start Sliver C2 for persistent access
use auxiliary/integration/sliver_c2
set ACTION start_server
run

# Start Havoc teamserver for team operations
use auxiliary/integration/havoc_c2
set ACTION start_teamserver
run
```

**Documentation:**
- [Shell Catcher & C2 Guide](documentation/SHELL_CATCHER_C2_GUIDE.md) - Comprehensive integration guide
- [Quick Reference](documentation/SHELL_CATCHER_C2_QUICKSTART.md) - Quick command reference
- [Integration README](lib/msf/core/integrations/README.md) - Technical integration details

**Why These Tools?**
- ✅ Scale better than basic netcat/multi-handler
- ✅ Automatic privilege escalation (pwncat-cs)
- ✅ Professional session management
- ✅ Secure encrypted communications
- ✅ Team collaboration features
- ✅ Modern evasion techniques

## Contributing

To contribute to Metasploit:

1. **Setup Development Environment:** Follow the instructions in the [Development Setup Guide](https://docs.metasploit.com/docs/development/get-started/setting-up-a-metasploit-development-environment.html) on GitHub.
2. **Clone the Repository:** Obtain the source code from the official repository.
3. **Submit a Pull Request:** After making changes, submit a pull request for review. Additional details can be found in the [Contributing Guide](https://github.com/rapid7/metasploit-framework/blob/master/CONTRIBUTING.md).
