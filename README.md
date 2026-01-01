## What Are We Doing Here?
<sub>certainly not acid</sub>

The goal here is most definitely not to be a dick to Rapid 7. They've provided us so much. When the metasploit project went under the wing of Rapid 7, I think prior to that a whitewater rafting company [citation needed], we all said it- "who owns it now? Oh ok." That was certainly a moment, not one we all remember, certainly not one that I remember, but almost entirely likely a possible reality.

This is an effort to change that reality, a lot like doing acid, but with slightly more focus on computers and less on trees and flowers swaying in a colorful wind. This project aims to bring reverse engineering, fuzzing, and the latest 'sploits to the msf framework. I've already put in some personal exploits, some personal tools, some new tools, and even *some tools that work*.

## What is this?

We used to like msf, ya know, back in the day. But now msf express, which I tried like 15 years ago (actually wait..2010, sh** yeah actually 15 years ago), was not a fun experience. The sales guy was not very nice to me, I found it a weird and clunky web app wrapper around msf and I found myself going "wtf can i just go back to the terminal." I didn't buy it, it was like 2k back then, i don't know what it is now, but hopefully they have nicer sales people.

Oh right, what is this then? It's metasploit, but first it's in a language people actually know. Second, it's an effort to bring together the best and 1337est actual security tools into one place, and it's an effort to use the open sourcety of msf as a little framework for exploits. Really, you gotta admit, whatever you might think about msf, it's easy to use, it lets you set the right fields you want, and sometimes, it might even work. That's pretty rad. But it's missing:

- Real port scanning - nmap integration is clunky, db is clunky and IMO a bit too abstracted from the user
- HOW IS STARTUP TIME LIKE 30 SECONDS?!!?!?!?! It's a CLI app!? And it's backed by a DATABASE for like what? A few thousand records of exploits and modules?? Who wrote that schema?! Normalize that shit pleaaaaseee. Or don't, now it doesn't matter, because we will. We'd contribute back, but all of our code is python. Sorry. 
- Just kidding- if you are Rapid 7 reading this, our ruby transpiler we wrote also goes the other way- that's right we have a bispiler, and if you use pf which will be integrated in this soon, you can convert to any language, so really, not to put it in a bucket, it's a panspiler. 
- What that means for you (everyone): write you're exploits in whatever you want. `pf` is a tool (seen in HyperionGray/pf-web-poly-compile-helper-runner) that does a little bit too much, but includes stuff like fuzzing, reverse engineering (with Ghidra and Radare2), debugging (lldb, gdb + pwndbg + pwntools + a handful of other helpers), exploit writing helpers like integration with pwndbg, heap spray helpers, ELF analyzers and stuff, x64dbg planned, and some educational material around all of that stuff. Why do you care? It also includes a ton of language conversion tools all under one hood.
- Language conversion tools- pf supports: FORTRAN, Julia, ASM, C, C++, Java (both android and normal people Java), Kotlin, Python, Node, Go, Rust, CUDA, JS, TS, Swift, Objective-C, C#, bash, fish, zsh, and some others I forget. So really- write your exploits in whatever you want. Write your rad tools in whatever you want- we'd love to take a look at 'em and integrate them.
- This is about community. Hacker community. Not the industry.

Thanks for reading.
- Alex/_hyp3ri0n/P4X




















---

# Original MSF Readme Below


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

**See also:**
- [Quick Start Guide](QUICKSTART.md) - Complete installation and usage instructions
- [Startup Methods Visual Guide](STARTUP_METHODS.md) - Detailed comparison of startup methods

## Latest Version
Access the latest version of Metasploit from the [Nightly Installers](https://docs.metasploit.com/docs/using-metasploit/getting-started/nightly-installers.html) page.

## Documentation
Comprehensive documentation, including usage guides, is available at [Metasploit Docs](https://docs.metasploit.com/).

## Features

### Python-Native Implementation
- **Modern Language**: Metasploit Framework rewritten in Python for better accessibility and performance
- **Faster Startup**: Significantly reduced startup time compared to Ruby implementation
- **7,456+ Python Modules**: Complete transpilation of all Ruby modules to Python

### Exploitation & Security Tools
- **Exploit Modules**: Comprehensive collection of exploit modules for various platforms and vulnerabilities
- **Auxiliary Modules**: Port scanning, fuzzing, protocol analysis, and reconnaissance tools
- **Payloads**: Wide variety of payloads for different architectures and operating systems
- **Post-Exploitation**: Extensive post-exploitation modules for maintaining access and gathering information

### Binary Analysis & Reverse Engineering
- **Radare2 Integration**: Advanced binary analysis with GDB-like command interface
- **LLDB Support**: Dynamic debugging capabilities for runtime analysis
- **Binary Instrumentation**: AFL-style coverage tracking and code path analysis
- **In-Memory Fuzzing**: High-speed fuzzing with stack manipulation

### Modern C2 & Shell Management
- **Sliver C2**: Professional Go-based C2 with mTLS, WireGuard, and HTTP(S) protocols
- **Havoc C2**: Modern C2 with GUI teamserver and advanced evasion techniques
- **pwncat-cs**: Advanced shell handler with automatic privilege escalation
- **Villain**: Web-based UI for managing multiple shells at scale

### Development Tools
- **Ruby ↔ Python Transpiler**: Bidirectional conversion between Ruby and Python code
- **Multi-Language Support**: Write exploits in Python, Ruby, or any supported language via PF framework
- **Pwntools Integration**: Industry-standard exploitation library built-in
- **Modern Tooling**: Black, flake8, isort for code quality; pytest for testing

### Database & Session Management
- **PostgreSQL Support**: Efficient database backend for storing scan results and session data
- **Session Handling**: Professional session management with encryption and team collaboration features
- **Workspace Organization**: Logical separation of different projects and engagements

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

## Features

### Core Capabilities

- **🐍 Python-Native Framework**: Complete transpilation of Ruby codebase to Python for better accessibility and performance
- **🎯 Extensive Exploit Database**: Thousands of exploits, payloads, and auxiliary modules for penetration testing
- **🔧 Module Development**: Easy-to-use framework for writing custom exploits in Python or Ruby
- **🌐 Network Exploitation**: Support for various protocols (HTTP, SMB, SSH, LDAP, Postgres, and more)
- **💉 Payload Generation**: Advanced payload creation with msfvenom for multiple platforms and architectures

### Advanced Tools

- **🔍 Binary Analysis**: Integrated Radare2 and LLDB for reverse engineering and debugging
  - GDB-like command interface for familiar workflow
  - AFL-style coverage tracking and instrumentation
  - In-memory fuzzing capabilities
- **🛠️ Modern C2 Frameworks**: Professional command-and-control integration
  - Sliver: Go-based C2 with encrypted channels (mTLS, WireGuard, HTTP(S), DNS)
  - Havoc: Modern C2 with GUI teamserver and advanced evasion
- **🔌 Enhanced Shell Handlers**: 
  - pwncat-cs: Automatic privilege escalation and post-exploitation
  - Villain: Web-based UI for managing multiple shells
- **🧬 Fuzzing Support**: AFL++, libFuzzer integration for vulnerability discovery

### Development & Integration

- **🔄 Bidirectional Transpilation**: Ruby ↔ Python conversion tools
- **📦 Language Flexibility**: Write exploits in multiple languages (Python, Ruby, C, C++, Go, Rust, and more)
- **🏗️ Modern Build System**: Python requirements.txt, pyproject.toml, and task automation
- **✅ Testing Infrastructure**: Comprehensive pytest-based testing with RSpec compatibility
- **🎨 Code Quality**: Automated linting with flake8, Black, isort, and Rubocop
- **🐛 Debugging Tools**: GDB, GEF, pwndbg integration for exploit development

### Exploitation Features

- **📚 Module Library**: 
  - Exploit modules for CVEs and custom vulnerabilities
  - Auxiliary modules for scanning, fuzzing, and information gathering
  - Post-exploitation modules for privilege escalation and persistence
- **🎭 Evasion Techniques**: Sleep obfuscation, indirect syscalls, and anti-analysis features
- **🔐 Session Management**: Multi-session handling with secure encrypted communications
- **👥 Team Collaboration**: Teamserver support for coordinated red team operations
- **📊 Database Integration**: PostgreSQL backend for tracking campaigns and results

### Compatibility

- **🔙 Legacy Support**: Pre-2020 Ruby modules maintained in `modules_legacy/` for compatibility
- **🐧 Cross-Platform**: Linux, macOS, and Windows support
- **🔌 API Access**: REST API and RPC interface for automation and integration
- **📖 Extensive Documentation**: Comprehensive guides, API docs, and examples

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

# Run tests with pytest (configured in pyproject.toml)
pytest
pytest -m unit  # Run only unit tests
pytest --cov=lib --cov=modules --cov-report=html  # With coverage

# Install Python dependencies
pip3 install -r requirements.txt
```

See also:
- **[docs/ruby2py/](docs/ruby2py/)** - **Complete Ruby→Python conversion documentation**
- [ruby2py/README.md](ruby2py/README.md) - Conversion tools usage guide
- [modules_legacy/README.md](modules_legacy/README.md) - Legacy module documentation
- [docs/TEST_COVERAGE_GUIDE.md](docs/TEST_COVERAGE_GUIDE.md) - Test coverage guide

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
- **[Test Coverage Guide](docs/TEST_COVERAGE_GUIDE.md)** - Test coverage strategy and best practices
- **[Code Quality Guidelines](CODE_QUALITY.md)** - Code quality standards and best practices
- **[Code Quality Guide](docs/CODE_QUALITY_GUIDE.md)** - Architecture and coding standards
- **[Security Best Practices](docs/SECURITY_BEST_PRACTICES.md)** - Secure coding guidelines
- **[Contributing Guide](CONTRIBUTING.md)** - Complete contribution guidelines
- **[Security Policy](SECURITY.md)** - Security vulnerability reporting
