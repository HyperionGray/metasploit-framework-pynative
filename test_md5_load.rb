#!/usr/bin/env ruby

# Quick test to see if the md5_lookup.rb file loads correctly
begin
  # Add the workspace lib directory to load path
  $LOAD_PATH.unshift(File.join(File.dirname(__FILE__), 'lib'))
  
  # Try to load the file
  load File.join(File.dirname(__FILE__), 'tools/password/md5_lookup.rb')
  
  puts "✓ File loaded successfully"
  
  # Test basic class instantiation
  disclaimer = Md5LookupUtility::Disclaimer.new
  puts "✓ Disclaimer class instantiated"
  
  lookup = Md5LookupUtility::Md5Lookup.new
  puts "✓ Md5Lookup class instantiated"
  
  # Test with empty argv for Driver
  driver = Md5LookupUtility::Driver.new([])
  puts "✓ Driver class instantiated with empty argv"
  
  puts "✓ OptsConsole class available" if defined?(Md5LookupUtility::OptsConsole)
  
  # Test OptsConsole with empty argv
  options = Md5LookupUtility::OptsConsole.parse([])
  puts "✓ OptsConsole.parse works with empty argv"
  puts "  Options: #{options}"
  
rescue => e
  puts "✗ Error: #{e.message}"
  puts e.backtrace.first(5)
end