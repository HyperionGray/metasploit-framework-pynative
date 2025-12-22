#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Metasploit Framework Environment Configuration (Python-native)

This file initializes the Metasploit Framework environment,
similar to how config/environment.rb initializes the Ruby environment.
"""

from pathlib import Path
import sys

# Add current directory to path
current_dir = Path(__file__).resolve().parent
if str(current_dir) not in sys.path:
    sys.path.insert(0, str(current_dir))

# Load application configuration
try:
    from . import application
except ImportError:
    import application

# Initialize the framework
config = application.initialize()

# Export commonly used configuration
MSF_ROOT = config.msf_root
MODULE_PATHS = config.module_paths
PLUGIN_PATH = config.plugin_path
DATA_ROOT = config.data_root

if __name__ == '__main__':
    print("Metasploit Framework Environment")
    print("=" * 70)
    print(f"MSF_ROOT: {MSF_ROOT}")
    print(f"MODULE_PATHS: {MODULE_PATHS}")
    print(f"PLUGIN_PATH: {PLUGIN_PATH}")
    print(f"DATA_ROOT: {DATA_ROOT}")
    print("\nFramework initialized and ready!")

