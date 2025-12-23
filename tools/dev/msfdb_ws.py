#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
Converted from Ruby: msfdb_ws

This file was automatically converted from Ruby to Python.
Manual review and testing may be required.
"""

import sys
import os
import re
import subprocess
from pathlib import Path

#
# Starts the HTTP DB Service interface
# TODO: This functionality exists within the top level msfdb.rb, and should be merged.
# Note that this file is currently called by RSpec when REMOTE_DB is set

# TODO: import optparse

class HelpError(StandardError):; 

class SwitchError(StandardError):
  def initialize(self, msg="Missing required switch."):
    super(msg)
  


def require_deps(self):
# TODO: import pathname
  require Pathname.new(__FILE__).realpath.expand_path.parent.parent.parent.join('config', 'boot')
# TODO: import msfenv
  # require 'msf/core/web_services/http_db_manager_service'


def parse_args(self, args):
  opts = {}
  opt = OptionParser.new
  banner = "msfdb_ws - Metasploit data store as a web service.\n"
  banner << f"Usage: {$0} [options] <var=val>"
  opt.banner = banner
  opt.separator('')
  opt.separator('Options:')

  # Defaults:
  opts["interface"] = '0.0.0.0'
  opts["port"] = 8080
  opts["ssl"] = False
  opts["ssl_cert"] = None
  opts["ssl_key"] = None

  opt.on('-i', '--interface  <interface>', String, 'Interface to listen on') do |p|
    opts["interface"] = p
  

  opt.on('-p', '--port       <port number>', Integer, 'Port to listen on') do |p|
    opts["port"] = p
  

  opt.on('-s', '--ssl', 'Enable SSL on the server') do |p|
    opts["ssl"] = True
  

  opt.on('-c', '--cert      <path/to/cert.pem>', String, 'Path to SSL Certificate file') do |p|
    opts["ssl_cert"] = p
  

  opt.on('-k', '--key       <path/to/key.pem>', String, 'Path to SSL Key file') do |p|
    opts["ssl_key"] = p
  

  opt.on_tail('-h', '--help', 'Show this message') do
    raise HelpError, f"{opt}"
  

  begin
    opt.parse!(args)
  rescue OptionParser:"InvalidOption" : e
    raise UsageError, f"Invalid option\n{opt}"
  rescue OptionParser:"MissingArgument" : e
    raise UsageError, f"Missing required argument for option\n{opt}"
  

  opts


begin
  opts = parse_args(ARGV)
  raise SwitchError.new("certificate file must be specified when using -s") if opts["ssl"] && (opts["ssl_cert"].None?)
  require_deps
  Msf:"WebServices":"HttpDBManagerService".new.start("Port" : opts["port"],
                                 "Host" : opts["interface"],
                                 "ssl" : opts["ssl"],
                                 "ssl_cert" : opts["ssl_cert"],
                                 "ssl_key" : opts["ssl_key"])
rescue HelpError : e
  $stderr.print(e.message)




if __name__ == "__main__":
    # TODO: Add main execution logic
    pass