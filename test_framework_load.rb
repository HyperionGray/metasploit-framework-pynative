#!/usr/bin/env ruby

# Test loading the md5_lookup.rb file the same way the test does
begin
  # Add the workspace lib directory to load path
  $LOAD_PATH.unshift(File.join(File.dirname(__FILE__), 'lib'))
  
  # Load the framework
  require 'metasploit/framework'
  
  # Load the file using the same method as the test
  load Metasploit::Framework.root.join('tools/password/md5_lookup.rb').to_path
  
  puts "✓ File loaded successfully using Metasploit::Framework.root"
  
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
  
  puts "✓ All classes and methods are available for testing"
  
rescue => e
  puts "✗ Error: #{e.message}"
  puts e.backtrace.first(10)
end