#!/usr/bin/env ruby
# -*- coding: binary -*-

class MsfVenomError < StandardError; end
class HelpError < StandardError; end
class UsageError < MsfVenomError; end

require 'optparse'
require 'timeout'

# Show informational message about Python alternatives (unless quiet mode)
unless ENV['MSF_QUIET'] || ARGV.include?('-q') || ARGV.include?('--quiet') || ARGV.include?('-h') || ARGV.include?('--help')
  puts "\n" + "="*70
  puts "  MsfVenom - Payload Generator (Legacy Ruby Version)"
  puts "="*70
  puts "  NOTE: This is the legacy Ruby version."
  puts "  For the primary Python-native experience, use:"
  puts "    python3 msfvenom.py"
  puts "="*70 + "\n"
end