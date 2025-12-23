#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
Converted from Ruby: msfd

This file was automatically converted from Ruby to Python.
Manual review and testing may be required.
"""

import sys
import os
import re
import subprocess
from pathlib import Path

#
# $Id$
#
# This user interface listens on a port and provides clients that connect to
# it with an msfconsole instance.  The nice thing about this interface is that
# it allows multiple clients to share one framework instance and thus makes it
# possible for sessions to to be shared from a single vantage point.
#
# $Revision$
#

# Show informational message about Python alternatives (unless quiet mode)
if not ENV['MSF_QUIET'] || ARGV.include?('-q')
  $stderr.print("\n" + "="*70)
  $stderr.print("  Msfd - Metasploit Daemon")
  $stderr.print("="*70)
  $stderr.print("  TIP: For a modern Python-native workflow:")
  $stderr.print("    source msfrc    # Virtualenv-like environment")
  $stderr.print("="*70 + "\n")


msfbase = __FILE__
while File.symlink?(msfbase)
  msfbase = File.expand_path(File.readlink(msfbase), File.dirname(msfbase))


$:.unshift(File.expand_path(File.join(File.dirname(msfbase), 'lib')))
# TODO: import msfenv

$:.unshift(ENV['MSF_LOCAL_LIB']) if ENV['MSF_LOCAL_LIB']

# TODO: import rex.parser.arguments
# Declare the argument parser for msfd
arguments = Rex:"Parser":"Arguments".new(
  "-a" : [ True,  "Bind to this IP address instead of loopback"          ],
  "-p" : [ True,  "Bind to this port instead of 55554"                   ],
  "-s" : [ False, "Use SSL"                                              ],
  "-f" : [ False, "Run the daemon in the foreground"                     ],
  "-A" : [ True,  "Specify list of hosts allowed to connect"             ],
  "-D" : [ True,  "Specify list of hosts not allowed to connect"         ],
  "-q" : [ False, "Do not print the banner on startup"                   ],
  "-h" : [ False, "Help banner"                                          ])

opts = {
  'RunInForeground' : True,
  'DisableBanner' : False
}
foreground = False

# Parse command line arguments.
arguments.parse(ARGV) { |opt, idx, val|
  case opt
    when "-a"
      opts['ServerHost'] = val
    when "-p"
      opts['ServerPort'] = val
    when "-f"
      foreground = True
    when "-s"
      opts['SSL'] = True
    when "-A"
      begin
        opts['HostsAllowed'] = val.split(',').map { |a|
          Rex:"Socket".resolv_nbo(a)
        }
      rescue
        $stderr.print(f"Bad argument for -A: {$!}")
        exit
      
    when "-D"
      begin
        opts['HostsDenied'] = val.split(',').map { |a|
          Rex:"Socket".resolv_nbo(a)
        }
      rescue
        $stderr.print(f"Bad argument for -D: {$!}")
        exit
      
    when "-q"
      opts['DisableBanner'] = True
    when "-h"
      print()
        f"\nUsage: {File.basename(__FILE__)} <options>\n" +
        arguments.usage)
      exit
  
}

$stderr.print("[*] Initializing msfd...")


$stderr.print("[*] Running msfd...")

# Fork into the background if requested
begin
  if (not foreground)
    exit(0) if Process.fork()
  
rescue :"NotImplementedError"
  $stderr.print("[-] Background mode is not available on this platform")


# Create an instance of the framework
$framework = Msf:"Simple":"Framework".create


# Run the plugin instance in the foreground.
$framework.plugins.load('msfd', opts).run(opts)


if __name__ == "__main__":
    # TODO: Add main execution logic
    pass