# Metasploit Framework Quick Start Guide

This guide will help you get started with the Python-native Metasploit Framework quickly.

## 🚀 Installation

### Prerequisites

- Python 3.8 or higher
- Ruby 3.0 or higher (for legacy modules)
- Git

### Clone the Repository

```bash
git clone https://github.com/HyperionGray/metasploit-framework-pynative.git
cd metasploit-framework-pynative
```

### Install Dependencies

```bash
# Install Python dependencies
pip3 install -r requirements.txt

# Install Ruby dependencies (for legacy modules)
bundle install
```

## 🐍 Getting Started - The Preferred Way

**The recommended way to use this fork is with the `source msfrc` method.** This gives you a virtualenv-like experience for Metasploit.

### Step 1: Activate MSF Environment

```bash
# Activate Metasploit environment (similar to Python virtualenv)
source msfrc
```

You'll see a confirmation message:
```
🐍 Metasploit Framework Environment Activated!

This gives you a Python virtual environment-like experience for MSF.
Type 'msf_info' for available commands or 'msf_console' to get started.

To deactivate: msf_deactivate
```

### Step 2: Use MSF Commands

Once activated, you have direct access to all MSF commands in your shell:

```bash
# Get information about your MSF environment
msf_info

# Start the Python-enhanced console
msf_console

# Generate payloads
msf_venom -l payloads

# Search for modules
msf_search apache

# Launch an exploit directly
msf_exploit modules/exploits/linux/http/example.py

# Manage the database
msf_db status

# Start RPC server
msf_rpc
```

### Step 3: Run Python Modules Directly

You can also run Python exploit modules directly:

```bash
# Get help for a specific module
python3 modules/exploits/linux/http/acronis_cyber_infra_cve_2023_45249.py --help

# Run a vulnerability check
python3 modules/exploits/linux/http/acronis_cyber_infra_cve_2023_45249.py \
    --host 192.168.1.100 --check-only --verbose

# Execute an exploit
python3 modules/exploits/linux/http/acronis_cyber_infra_cve_2023_45249.py \
    --host 192.168.1.100 --target 1 --ssl --verbose
```

### Step 4: Deactivate When Done

```bash
# Restore your original shell environment
msf_deactivate
```

## ✅ Why Use `source msfrc`?

The `source msfrc` approach provides several advantages:

- 🚀 **Modern workflow** - Works like Python virtualenv activation
- 💻 **Direct shell access** - All MSF commands available in your regular shell (no need to enter msfconsole)
- 🐍 **Python-native** - Run Python modules directly with proper environment
- 🔧 **Easy access** - Transpiler tools and utilities right at your fingertips
- 📦 **Auto-configured** - Environment variables automatically set
- 🧹 **Clean deactivation** - Simple `msf_deactivate` to restore your shell

## ⚠️ What About `msfconsole`?

If you try to run `./msfconsole` directly (without activating the MSF environment), you'll see a helpful message guiding you to use `source msfrc` instead.

The traditional `msfconsole` approach is being phased out in this fork in favor of the more flexible and Python-native `source msfrc` method.

## 📚 Additional Commands Available After Activation

Once you've run `source msfrc`, these commands become available:

| Command | Description |
|---------|-------------|
| `msf_console` | Start Python-enhanced MSF console |
| `msf_venom` | Payload generator |
| `msf_exploit` | Quick exploit launcher |
| `msf_check` | Vulnerability checker |
| `msf_search` | Search for modules |
| `msf_db` | Database management |
| `msf_rpc` | RPC server |
| `msf_update` | Update framework |
| `msf_info` | Show environment information |
| `msf_deactivate` | Exit MSF environment |

## 🔄 Using Transpiler Tools

This fork includes powerful bidirectional transpilers:

### Ruby to Python

```bash
# Convert a Ruby module to Python
python3 ruby2py/convert.py modules/exploits/windows/smb/old_exploit.rb

# Convert with custom output
python3 ruby2py/convert.py input.rb -o output.py

# Batch convert directory (coming soon)
python3 ruby2py/convert.py modules/exploits/linux/http/ --recursive
```

### Python to Ruby

```bash
# Convert a Python module to Ruby
python3 ruby2py/py2ruby/transpiler.py new_exploit.py -o output.rb

# With verbose output
python3 ruby2py/py2ruby/transpiler.py new_exploit.py -o output.rb --verbose
```

## 🛠️ Development Workflow

### Writing a New Exploit

1. Activate MSF environment: `source msfrc`
2. Create your Python exploit module
3. Test it: `python3 modules/exploits/path/to/your_exploit.py --help`
4. Run checks: `python3 modules/exploits/path/to/your_exploit.py --check-only`
5. Test exploitation: `python3 modules/exploits/path/to/your_exploit.py --host TARGET`

### Converting Legacy Ruby Modules

1. Activate MSF environment: `source msfrc`
2. Convert: `python3 ruby2py/convert.py path/to/ruby_module.rb`
3. Review the generated Python code
4. Test the converted module
5. Make any necessary adjustments

## 📖 Next Steps

- Read the [Usage Guide](docs/USAGE.md) for detailed information
- Check out the [Exploit Writing Guide](documentation/EXPLOIT_WRITING_GUIDE.md)
- Explore [PF Integration](documentation/PF_INTEGRATION_GUIDE.md) for advanced tools
- Review [Module Categorization](documentation/MODULE_CATEGORIZATION.md)
- See the [Contributing Guide](CONTRIBUTING.md) to contribute

## 💡 Tips

1. **Always activate first**: Get in the habit of running `source msfrc` when starting work
2. **Use msf_info**: Run `msf_info` to see all available commands
3. **Direct execution**: Python modules can be run directly without entering a console
4. **Environment variables**: All necessary paths are automatically configured
5. **Clean exit**: Use `msf_deactivate` when switching to other projects

## 🆘 Getting Help

- **GitHub Discussions**: [Ask questions and share ideas](https://github.com/rapid7/metasploit-framework/discussions)
- **Slack**: [Join Metasploit Slack](https://metasploit.com/slack)
- **Documentation**: [Metasploit Docs](https://docs.metasploit.com/)
- **API Docs**: [Framework API](https://rapid7.github.io/metasploit-framework/api/)

## 📝 Example Session

Here's a complete example session:

```bash
# Clone and setup (one-time)
git clone https://github.com/HyperionGray/metasploit-framework-pynative.git
cd metasploit-framework-pynative
pip3 install -r requirements.txt

# Start working (every session)
source msfrc

# Explore the environment
msf_info

# Search for an exploit
msf_search apache

# Run a module directly
python3 modules/exploits/linux/http/apache_example.py --help

# Clean up
msf_deactivate
```

Welcome to the Python-native Metasploit Framework! 🎉
