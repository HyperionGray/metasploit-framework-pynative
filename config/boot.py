#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Metasploit Framework Boot Configuration
Python implementation of config/boot.rb
"""

import os
import sys
from pathlib import Path

# Get the root directory of the framework
MSF_ROOT = Path(__file__).parent.parent.resolve()

# Add framework paths to Python path
sys.path.insert(0, str(MSF_ROOT / 'lib'))
sys.path.insert(0, str(MSF_ROOT))

# Set environment variables
os.environ.setdefault('MSF_ROOT', str(MSF_ROOT))
os.environ.setdefault('MSF_CONFIG_ROOT', str(MSF_ROOT / 'config'))
os.environ.setdefault('MSF_DATA_ROOT', str(MSF_ROOT / 'data'))
os.environ.setdefault('MSF_MODULE_PATHS', str(MSF_ROOT / 'modules'))
os.environ.setdefault('MSF_PLUGIN_PATHS', str(MSF_ROOT / 'plugins'))

# Database configuration
database_config_file = MSF_ROOT / 'config' / 'database.yml'
if database_config_file.exists():
    os.environ.setdefault('MSF_DATABASE_CONFIG', str(database_config_file))

# Python-specific configuration
config = {
    'msf_root': MSF_ROOT,
    'config_root': MSF_ROOT / 'config',
    'data_root': MSF_ROOT / 'data',
    'module_paths': [MSF_ROOT / 'modules'],
    'plugin_paths': [MSF_ROOT / 'plugins'],
    'lib_paths': [MSF_ROOT / 'lib'],
    'python_mode': True,
    'debug': os.environ.get('MSF_DEBUG', '0') == '1',
    'quiet': os.environ.get('MSF_QUIET', '0') == '1',
}

def initialize_framework():
    """Initialize the Python MSF framework"""
    try:
        # Try to import the main framework
        import msf
        return True
    except ImportError as e:
        if not config['quiet']:
            print(f"Warning: Could not load Python MSF framework: {e}")
            print("Falling back to Ruby framework...")
        return False

# Auto-initialize if this module is imported
_framework_initialized = initialize_framework()
