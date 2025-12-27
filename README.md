# Metasploit Framework

The Metasploit Framework is an open-source tool released under a BSD-style license. For detailed licensing information, refer to the `COPYING` file.

## 🚀 Quick Start

**New to this fork? Start here:** [Quick Start Guide](QUICKSTART.md)

The preferred way to use this Python-native fork is:

```bash
# Activate MSF environment (like Python virtualenv)
source msfrc

# Now use MSF commands directly in your shell
msf_info      # Show environment info
msf_console   # Start console
msf_exploit   # Launch exploits
```

See the [Quick Start Guide](QUICKSTART.md) for complete installation and usage instructions.

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

## Python-Native Framework (Round 4) - TRANSPILATION COMPLETE! 🎉

🐍 **ALL RUBY FILES HAVE BEEN TRANSPILED TO PYTHON!** 🐍

This fork has successfully converted Metasploit Framework to Python:

- **✅ 7,456 Python Files Created**: Every Ruby module now has a Python equivalent
- **✅ Config Files Converted**: All Ruby configs → Python configs
- **✅ Python Build System**: requirements.txt, pyproject.toml, tasks.py
- **✅ Python Linting**: .flake8, Black, isort configuration
- **✅ Full Transpilation Report**: See [RUBY_TO_PYTHON_COMPLETE.md](RUBY_TO_PYTHON_COMPLETE.md)

### What Was Transpiled

- **Post-2020 Modules**: Converted to Python (`modules/`)
- **Pre-2020 Modules**: Maintained in Ruby for compatibility (`modules_legacy/`)
- **Framework Core**: All `lib/` Ruby files → Python equivalents
- **Tests**: All RSpec tests → Python test files
- **Tools**: All Ruby tools → Python tools
- **Configuration**: Gemfile → requirements.txt, Rakefile → tasks.py

See [docs/ruby2py/TRANSPILATION_REPORT.md](docs/ruby2py/TRANSPILATION_REPORT.md) for detailed statistics.

### Transpilation Tools

**All Ruby files have been transpiled!** Tools available for future conversions:

#### Ruby → Python Converter
```bash
# Convert a single Ruby module to Python
python3 ruby2py/convert.py modules/exploits/path/to/module.rb

# Convert with output file specified
python3 ruby2py/convert.py input.rb -o output.py

# Convert entire directory recursively
python3 ruby2py/convert.py modules/exploits/linux/http/ --recursive
```

#### Python → Ruby Transpiler
```bash
# Transpile Python code back to Ruby
python3 ruby2py/py2ruby/transpiler.py script.py -o output.rb
```

See [ruby2py/README.md](ruby2py/README.md) for complete documentation.

### Quick Start with Python Modules

```bash
# View transpilation report
cat docs/ruby2py/RUBY_TO_PYTHON_COMPLETE.md

# Run Python module example
python3 modules/exploits/multi/http/generic_rce_example_2024.py

# Run Python tasks
python3 tasks.py test
python3 tasks.py lint

# Install Python dependencies
pip3 install -r requirements.txt
```

See also:
- **[docs/ruby2py/](docs/ruby2py/)** - **Complete Ruby→Python conversion documentation**
- [ruby2py/README.md](ruby2py/README.md) - Conversion tools usage guide
- [modules_legacy/README.md](modules_legacy/README.md) - Legacy module documentation

## Binary Analysis with Radare2

This fork includes advanced binary analysis capabilities with Radare2 integration:

- **GDB-like Commands**: Intuitive interface to Radare2 using familiar GDB syntax
- **LLDB Integration**: Dynamic debugging support for runtime analysis
- **Binary Instrumentation**: AFL-style coverage tracking and code path analysis  
- **In-Memory Fuzzing**: High-speed fuzzing with stack manipulation

See [docs/RADARE2_QUICKSTART.md](docs/RADARE2_QUICKSTART.md) for installation and usage guide.

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

### 🐍 Python-Native Experience (Recommended)

**The preferred way to use this fork is with the `source msfrc` method**, which gives you a virtualenv-like experience for Metasploit:

```bash
# Activate Metasploit environment (similar to Python virtualenv)
source msfrc

# Now MSF commands are available in your shell
msf_console    # Python-enhanced console
msf_venom      # Payload generator
msf_exploit    # Quick exploit launcher
msf_search     # Search modules
msf_info       # Show environment info

# Run Python exploit modules directly
python3 modules/exploits/linux/http/example.py --help

# Use transpiler tools
python3 ruby2py/convert.py old_module.rb
python3 ruby2py/py2ruby/transpiler.py new_module.py -o output.rb

# Deactivate when done
msf_deactivate
```

**Why use `source msfrc`?**
- ✅ **Modern workflow** - Works like Python virtualenv activation
- ✅ **Direct shell access** - All MSF commands available in your regular shell (no need to enter msfconsole)
- ✅ **Python-native** - Run Python modules directly with proper environment
- ✅ **Easy access** - Transpiler tools and utilities right at your fingertips
- ✅ **Auto-configured** - Environment variables automatically set
- ✅ **Clean deactivation** - Simple `msf_deactivate` to restore your shell

### Classic Console Experience (Legacy)

If you try running `msfconsole` directly, you'll be prompted to use the recommended `source msfrc` method instead.

For traditional Metasploit console usage (not recommended for this fork):
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
3. **Submit a Pull Request:** After making changes, submit a pull request for review. Additional details can be found in the [Contributing Guide](CONTRIBUTING.md).

### Developer Resources

- **[Developer Quick Start Guide](docs/DEVELOPMENT_GUIDE.md)** - Quick start guide for new contributors
- **[Testing Guide](TESTING.md)** - Comprehensive testing documentation
- **[Code Quality Guidelines](CODE_QUALITY.md)** - Code quality standards and best practices
- **[Contributing Guide](CONTRIBUTING.md)** - Complete contribution guidelines
- **[Security Policy](.github/SECURITY.md)** - Security vulnerability reporting
