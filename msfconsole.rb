#!/usr/bin/env ruby
# -*- coding: binary -*-
#
# This user interface provides users with a command console interface to the
# framework.
#

require 'pathname'
begin

  # Show informational message about Python-native alternative
  unless ENV['MSF_QUIET'] || ARGV.include?('-q') || ARGV.include?('--quiet')
    puts "\n" + "="*70
    puts "  Metasploit Framework - Legacy Ruby Console"
    puts "="*70
    puts "  NOTE: This is the legacy Ruby version."
    puts "  For the primary Python-native experience, use:"
    puts "    python3 msfconsole.py"
    puts ""
    puts "  Python modules available in: modules/"
    puts "="*70 + "\n"
  end

  # Silences warnings as they only serve to confuse end users
  if defined?(Warning) && Warning.respond_to?(:[]=)
    Warning[:deprecated] = false unless ENV['CI']
  end

  # @see https://github.com/rails/rails/blob/v3.2.17/railties/lib/rails/generators/rails/app/templates/script/rails#L3-L5
  require Pathname.new(__FILE__).realpath.expand_path.parent.join('config', 'boot')
  require 'metasploit/framework/profiler'
  Metasploit::Framework::Profiler.start

  require 'msfenv'
  require 'metasploit/framework/command/console'
  Metasploit::Framework::Command::Console.start
rescue Interrupt
  puts "\nAborting..."
  exit(1)
end