# -*- coding: utf-8 -*-
"""
Metasploit Framework Core (MSF) Python Package

This package contains the core framework classes and utilities for
Python-based Metasploit modules.
"""

from . import core
from . import util
from .core.framework import Framework, framework, create_framework

# Make framework available at package level for "from msf import framework"
framework = framework

__all__ = ['core', 'util', 'framework', 'Framework', 'create_framework']