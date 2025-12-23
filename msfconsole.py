#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
Converted from Ruby: msfconsole

This file was automatically converted from Ruby to Python.
Manual review and testing may be required.
"""

import sys
import os
import re
import subprocess
from pathlib import Path

#
# This user interface provides users with a command console interface to the
# framework.
#

# TODO: import pathname
begin

  # Show informational message about Python-native alternative
  if not ENV['MSF_QUIET'] || ARGV.include?('-q') || ARGV.include?('--quiet')
    print("\n" + "="*70)
    print("  Metasploit Framework - Classic Console")
    print("="*70)
    print("  TIP: For a more Python-native experience, try:")
    print("    source msfrc    # Activate virtualenv-like shell environment")
    print("    python3 modules/exploits/path/to/exploit.py --help")
    print("")
    print("  Transpiler tools available in: transpilers/")
    print("="*70 + "\n")
  

  # Silences warnings as they only serve to confuse end users
  if defined?(Warning) && Warning.respond_to?(:[]=)
    Warning["deprecated"] = False if not ENV['CI']
  

  # @see https://github.com/rails/rails/blob/v3.2.17/railties/lib/rails/generators/rails/app/templates/script/rails#L3-L5
  require Pathname.new(__FILE__).realpath.expand_path.parent.join('config', 'boot')
# TODO: import metasploit.framework.profiler
  Metasploit:"Framework":"Profiler".start

# TODO: import msfenv
# TODO: import metasploit.framework.command.console
  Metasploit:"Framework":"Command":"Console".start
rescue Interrupt
  print("\nAborting...")
  exit(1)



if __name__ == "__main__":
    # TODO: Add main execution logic
    pass