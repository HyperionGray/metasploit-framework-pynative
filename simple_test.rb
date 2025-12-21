#!/usr/bin/env ruby

# Minimal test to check Ruby wrapper loading
puts "Testing md5_lookup.rb wrapper..."

# Add lib to load path
$LOAD_PATH.unshift(File.join(File.dirname(__FILE__), 'lib'))

begin
  # Try to load msfenv first
  require 'msfenv'
  puts "✓ msfenv loaded"
  
  # Try to load the wrapper
  load File.join(File.dirname(__FILE__), 'tools', 'password', 'md5_lookup.rb')
  puts "✓ md5_lookup.rb loaded"
  
  # Test class instantiation
  disclaimer = Md5LookupUtility::Disclaimer.new
  puts "✓ Disclaimer instantiated"
  
  lookup = Md5LookupUtility::Md5Lookup.new
  puts "✓ Md5Lookup instantiated"
  
  driver = Md5LookupUtility::Driver.new
  puts "✓ Driver instantiated"
  
  puts "✓ All tests passed!"
  
rescue LoadError => e
  puts "✗ LoadError: #{e.message}"
  puts e.backtrace.join("\n")
  exit 1
rescue => e
  puts "✗ Error: #{e.message}"
  puts e.backtrace.join("\n")
  exit 1
end