#!/usr/bin/env ruby
# -*- coding: binary -*-
#
# $Id$
#
# This keeps the framework up-to-date
#
# $Revision$
#

# Show informational message about Python alternatives (unless quiet mode)
unless ENV['MSF_QUIET'] || ARGV.include?('-q')
  $stderr.puts "\n" + "="*70
  $stderr.puts "  MsfUpdate - Framework Updater (Legacy Ruby Version)"
  $stderr.puts "="*70
  $stderr.puts "  NOTE: This is the legacy Ruby version."
  $stderr.puts "  For the primary Python-native experience, use:"
  $stderr.puts "    python3 msfupdate.py"
  $stderr.puts "="*70 + "\n"
end

msfbase = __FILE__
while File.symlink?(msfbase)
  msfbase = File.expand_path(File.readlink(msfbase), File.dirname(msfbase))
end

class Msfupdate
  attr_reader :stdin
  attr_reader :stdout
  attr_reader :stderr