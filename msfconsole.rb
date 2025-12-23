#!/usr/bin/env ruby
# -*- coding: binary -*-
#
# This user interface provides users with a command console interface to the
# framework.
#

# Show guidance message for Python-enhanced experience
unless ENV['MSF_QUIET'] == '1'
  puts ""
  puts "🐍 Metasploit Framework - Traditional Ruby Console"
  puts ""
  puts "💡 For an enhanced Python experience, try:"
  puts "   source msfrc          # Activate MSF shell environment"
  puts "   msf_console           # Python-enhanced console"
  puts ""
  puts "   Or set MSF_QUIET=1 to hide this message"
  puts ""
end

require 'pathname'
begin

  # Show informational message about Python-native alternative
  unless ENV['MSF_QUIET'] || ARGV.include?('-q') || ARGV.include?('--quiet')
    puts "\n" + "="*70
    puts "  Metasploit Framework - Classic Console"
    puts "="*70
    puts "  TIP: For a more Python-native experience, try:"
    puts "    source msfrc    # Activate virtualenv-like shell environment"
    puts "    python3 modules/exploits/path/to/exploit.py --help"
    puts ""
    puts "  Transpiler tools available in: transpilers/"
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