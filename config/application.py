#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Metasploit Framework Application Configuration (Python-native)

This file contains the main application configuration for the
Python-native Metasploit Framework.
"""

import os
import sys
import logging
from pathlib import Path
from typing import Dict, Any

# Add config directory to path for imports
config_dir = Path(__file__).resolve().parent
sys.path.insert(0, str(config_dir))

# Import boot configuration
try:
    from . import boot
except ImportError:
    import boot

# Application configuration
class MetasploitConfig:
    """Configuration class for Metasploit Framework"""
    
    def __init__(self):
        self.msf_root = boot.MSF_ROOT
        self.debug = os.environ.get('MSF_DEBUG', '').lower() in ('1', 'true', 'yes')
        self.verbose = os.environ.get('MSF_VERBOSE', '').lower() in ('1', 'true', 'yes')
        
        # Database configuration
        self.database_config = self.msf_root / 'config' / 'database.yml'
        
        # Module paths
        self.module_paths = [
            self.msf_root / 'modules',
            self.msf_root / 'python_framework',
        ]
        
        # Add custom module paths from environment
        custom_paths = os.environ.get('MSF_MODULE_PATHS', '')
        if custom_paths:
            for path in custom_paths.split(':'):
                if path:
                    self.module_paths.append(Path(path))
        
        # Plugin configuration
        self.plugin_path = self.msf_root / 'plugins'
        
        # Data directories
        self.data_root = self.msf_root / 'data'
        self.cache_dir = Path.home() / '.msf4' / 'cache'
        self.log_dir = Path.home() / '.msf4' / 'logs'
        
        # Ensure directories exist
        self._ensure_directories()
        
        # Logging configuration
        self._setup_logging()
    
    def _ensure_directories(self):
        """Create necessary directories if they don't exist"""
        for directory in [self.cache_dir, self.log_dir]:
            directory.mkdir(parents=True, exist_ok=True)
    
    def _setup_logging(self):
        """Configure logging based on debug/verbose settings"""
        log_level = logging.DEBUG if self.debug else (
            logging.INFO if self.verbose else logging.WARNING
        )
        
        log_format = '%(asctime)s - %(name)s - %(levelname)s - %(message)s'
        
        # Configure root logger
        logging.basicConfig(
            level=log_level,
            format=log_format,
            handlers=[
                logging.StreamHandler(),
                logging.FileHandler(self.log_dir / 'metasploit.log')
            ]
        )
        
        self.logger = logging.getLogger('metasploit')
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert configuration to dictionary"""
        return {
            'msf_root': str(self.msf_root),
            'debug': self.debug,
            'verbose': self.verbose,
            'database_config': str(self.database_config),
            'module_paths': [str(p) for p in self.module_paths],
            'plugin_path': str(self.plugin_path),
            'data_root': str(self.data_root),
            'cache_dir': str(self.cache_dir),
            'log_dir': str(self.log_dir),
        }

# Global configuration instance
config = MetasploitConfig()

def get_config() -> MetasploitConfig:
    """Get the global configuration instance"""
    return config

def initialize():
    """Initialize the Metasploit Framework application"""
    boot.setup_environment()
    config.logger.info("Metasploit Framework initialized")
    config.logger.info(f"MSF_ROOT: {config.msf_root}")
    config.logger.info(f"Module paths: {config.module_paths}")
    return config

if __name__ == '__main__':
    print("Metasploit Framework Application Configuration")
    print("=" * 70)
    cfg = initialize()
    for key, value in cfg.to_dict().items():
        print(f"{key}: {value}")

