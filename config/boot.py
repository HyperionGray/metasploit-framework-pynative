#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Metasploit Framework Boot Configuration (Python-native)

This file sets up the Python environment for Metasploit Framework,
similar to how config/boot.rb sets up the Ruby environment.
"""

import os
import sys
from pathlib import Path

# Determine MSF root directory
MSF_ROOT = Path(__file__).resolve().parent.parent

# Add lib directory to Python path
LIB_PATH = MSF_ROOT / 'lib'
if str(LIB_PATH) not in sys.path:
    sys.path.insert(0, str(LIB_PATH))

# Add python_framework to path
PYTHON_FRAMEWORK_PATH = MSF_ROOT / 'python_framework'
if str(PYTHON_FRAMEWORK_PATH) not in sys.path:
    sys.path.insert(0, str(PYTHON_FRAMEWORK_PATH))

# Set environment variables
os.environ.setdefault('MSF_ROOT', str(MSF_ROOT))
os.environ.setdefault('MSF_MODULE_PATHS', str(MSF_ROOT / 'modules'))
os.environ.setdefault('MSF_PLUGIN_PATH', str(MSF_ROOT / 'plugins'))
os.environ.setdefault('MSF_DATA_ROOT', str(MSF_ROOT / 'data'))

# Configuration dictionary
config = {
    'msf_root': MSF_ROOT,
    'lib_path': LIB_PATH,
    'python_framework_path': PYTHON_FRAMEWORK_PATH,
    'module_paths': [MSF_ROOT / 'modules'],
    'plugin_path': MSF_ROOT / 'plugins',
    'data_root': MSF_ROOT / 'data',
}

def setup_environment():
    """
    Set up the Python environment for Metasploit Framework.
    Call this function to ensure all paths and settings are configured.
    """
    # Ensure MSF_ROOT is in PATH
    if str(MSF_ROOT) not in os.environ.get('PATH', ''):
        os.environ['PATH'] = f"{MSF_ROOT}:{os.environ.get('PATH', '')}"
    
    # Set Python-specific environment
    os.environ.setdefault('PYTHONUNBUFFERED', '1')
    
    return config

if __name__ == '__main__':
    print("Metasploit Framework Python Boot Configuration")
    print(f"MSF_ROOT: {MSF_ROOT}")
    print(f"LIB_PATH: {LIB_PATH}")
    print(f"PYTHON_FRAMEWORK_PATH: {PYTHON_FRAMEWORK_PATH}")
    print("\nCall setup_environment() to configure the environment.")

