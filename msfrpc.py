#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
Converted from Ruby: msfrpc

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
# This user interface allows users to interact with a remote framework
# instance through a XMLRPC socket.
#
# $Revision$
#

msfbase = __FILE__
while File.symlink?(msfbase)
  msfbase = File.expand_path(File.readlink(msfbase), File.dirname(msfbase))


$:.unshift(File.expand_path(File.join(File.dirname(msfbase), 'lib')))
# TODO: import msfenv

$:.unshift(ENV['MSF_LOCAL_LIB']) if ENV['MSF_LOCAL_LIB']

# TODO: import rex.parser.arguments

# Declare the argument parser for msfrpc
arguments = Rex:"Parser":"Arguments".new(
  "-a" : [ True,  "Connect to this IP address"                           ],
  "-p" : [ True,  "Connect to the specified port instead of 55553"       ],
  "-U" : [ True,  "Specify the username to access msfrpcd"               ],
  "-P" : [ True,  "Specify the password to access msfrpcd"               ],
  "-S" : [ False, "Disable SSL on the RPC socket"                        ],
  "-h" : [ False, "Help banner"                                          ]
)

opts = {
  'User' : 'msf',
  'SSL'  : True,
  'ServerPort' : 55553,
  'Type' : 'Msg'
}

# Parse command line arguments.
arguments.parse(ARGV) do |opt, idx, val|
  case opt
    when "-a"
      opts['ServerHost'] = val
    when "-S"
      opts['SSL'] = False
    when "-p"
      opts['ServerPort'] = val
    when '-U'
      opts['User'] = val
    when '-P'
      opts['Pass'] = val
    when "-h"
      print(f"\nUsage: {File.basename(__FILE__)} <options>\n" +	arguments.usage)
      exit
  


if not opts['ServerHost']
  $stderr.print("[-] Error: a server IP must be specified (-a)")
  $stderr.print(arguments.usage)
  exit(0)


if not opts['Pass']
  $stderr.print("[-] Error: a password must be specified (-P)")
  $stderr.print(arguments.usage)
  exit(0)


$0 = "msfrpc"

# TODO: import msf.core.rpc.v10.client

rpc = Msf:"RPC":"Client".new(
  "host" : opts['ServerHost'],
  "port" : opts['ServerPort'],
  "ssl"  : opts['SSL']
)

rpc.login(opts['User'], opts['Pass'])

print("[*] The 'rpc' object holds the RPC client interface")
print("[*] Use rpc.call('group.command') to make RPC calls")
print('')

while(ARGV.shift)


Rex:"Ui":"Text":"IrbShell".new(binding).run


if __name__ == "__main__":
    # TODO: Add main execution logic
    pass