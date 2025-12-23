#!/usr/bin/env ruby

# Quick syntax check for md5_lookup.rb
begin
  require_relative 'tools/password/md5_lookup.rb'
  puts "✓ Ruby file loads successfully"
  puts "✓ Md5LookupUtility module defined: #{defined?(Md5LookupUtility)}"
  puts "✓ Disclaimer class defined: #{defined?(Md5LookupUtility::Disclaimer)}"
  puts "✓ Md5Lookup class defined: #{defined?(Md5LookupUtility::Md5Lookup)}"
  puts "✓ Driver class defined: #{defined?(Md5LookupUtility::Driver)}"
  puts "✓ OptsConsole class defined: #{defined?(Md5LookupUtility::OptsConsole)}"
rescue LoadError => e
  puts "✗ LoadError: #{e.message}"
rescue SyntaxError => e
  puts "✗ SyntaxError: #{e.message}"
rescue => e
  puts "✗ Error: #{e.class}: #{e.message}"
end