#!/usr/bin/env ruby

# Mimic what the test does
puts "Mimicking the test loading process..."

begin
  # Add lib to load path like the test environment would
  $LOAD_PATH.unshift(File.join(File.dirname(__FILE__), 'lib'))
  
  require 'pathname'
  
  # This is what the test does - it uses Metasploit::Framework.root.join
  # Let's simulate this
  require 'msfenv'
  
  # Check if Metasploit::Framework is already defined
  if defined?(Metasploit::Framework)
    puts "✓ Metasploit::Framework is already defined"
  else
    puts "! Metasploit::Framework not defined, creating mock"
    # Create a mock Metasploit::Framework.root object
    module Metasploit
      module Framework
        def self.root
          Pathname.new('/workspace')
        end
      end
    end
  end
  
  # Now try to load like the test does
  load Metasploit::Framework.root.join('tools/password/md5_lookup.rb').to_path
  puts "✓ File loaded successfully using test method"
  
  # Try to instantiate classes
  disclaimer = Md5LookupUtility::Disclaimer.new
  puts "✓ Disclaimer class works"
  
  lookup = Md5LookupUtility::Md5Lookup.new
  puts "✓ Md5Lookup class works"
  
  puts "✓ Test simulation successful!"
  
rescue => e
  puts "✗ Error: #{e.message}"
  puts e.backtrace.join("\n")
  exit 1
end