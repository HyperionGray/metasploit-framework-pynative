# -*- coding: utf-8 -*-
"""
Metasploit Framework Python Library

This package contains the core Python implementation of the Metasploit Framework,
including exploit modules, auxiliary modules, payloads, and supporting utilities.
"""

__version__ = "6.4.0-dev"
__author__ = "Rapid7"
__license__ = "BSD-3-Clause"

# Core framework imports
from . import msf
from . import rex

__all__ = ['msf', 'rex']