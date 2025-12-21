# Python Framework Plugins

This directory contains Python versions of Metasploit Framework plugins.

## Available Plugins

- `token_adduser.py` - Attempt to add user accounts via incognito using all connected meterpreter sessions

## Plugin Structure

Python plugins follow the framework's plugin architecture with:
- Plugin class inheriting from `msf.core.plugin.Plugin`
- Command dispatcher for console commands
- Proper cleanup and resource management
- Metadata for framework registration

## Usage

Plugins are loaded automatically by the framework or can be loaded manually via the console.