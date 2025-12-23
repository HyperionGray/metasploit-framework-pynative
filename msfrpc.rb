#!/usr/bin/env ruby
# -*- coding: binary -*-
#
# $Id$
#
# This user interface allows users to interact with a remote framework
# instance through a XMLRPC socket.
#
# $Revision$
#

# Show informational message about Python alternatives (unless quiet mode)
unless ENV['MSF_QUIET'] || ARGV.include?('-q')
  $stderr.puts "\n" + "="*70
  $stderr.puts "  MsfRPC - Remote Procedure Call Interface (Legacy Ruby Version)"
  $stderr.puts "="*70
  $stderr.puts "  NOTE: This is the legacy Ruby version."
  $stderr.puts "  For the primary Python-native experience, use:"
  $stderr.puts "    python3 msfrpc.py"
  $stderr.puts "="*70 + "\n"
end

msfbase = __FILE__
while File.symlink?(msfbase)
  msfbase = File.expand_path(File.readlink(msfbase), File.dirname(msfbase))
end

$:.unshift(File.expand_path(File.join(File.dirname(msfbase), 'lib')))
require 'msfenv'

$:.unshift(ENV['MSF_LOCAL_LIB']) if ENV['MSF_LOCAL_LIB']