#!/usr/bin/env ruby

# Test if the file can be loaded the same way the test does it
puts "Testing file loading like the spec does..."

begin
  # Set up the load path
  $LOAD_PATH.unshift(File.expand_path('lib', __dir__))
  
  # Load required dependencies
  require 'pathname'
  
  # Try to load msfenv
  puts "Loading msfenv..."
  require 'msfenv'
  puts "✓ msfenv loaded"
  
  # Check what Metasploit::Framework provides
  if defined?(Metasploit::Framework) && Metasploit::Framework.respond_to?(:root)
    puts "✓ Metasploit::Framework.root is available"
    root_path = Metasploit::Framework.root
    puts "  Root path: #{root_path}"
  else
    puts "! Metasploit::Framework.root not available, will mock it"
    module Metasploit
      module Framework
        def self.root
          Pathname.new(__dir__)
        end
      end
    end
  end
  
  # Try to load the file
  file_path = Metasploit::Framework.root.join('tools/password/md5_lookup.rb').to_path
  puts "Attempting to load: #{file_path}"
  
  if File.exist?(file_path)
    puts "✓ File exists"
    load file_path
    puts "✓ File loaded successfully"
    
    # Test basic functionality
    if defined?(Md5LookupUtility)
      puts "✓ Md5LookupUtility module defined"
      
      if defined?(Md5LookupUtility::Disclaimer)
        disclaimer = Md5LookupUtility::Disclaimer.new
        puts "✓ Disclaimer class works"
      end
      
      if defined?(Md5LookupUtility::Md5Lookup)
        lookup = Md5LookupUtility::Md5Lookup.new
        puts "✓ Md5Lookup class works"
      end
      
    else
      puts "✗ Md5LookupUtility module not defined"
    end
    
  else
    puts "✗ File does not exist: #{file_path}"
  end
  
rescue => e
  puts "✗ Error: #{e.class}: #{e.message}"
  puts "Backtrace:"
  puts e.backtrace.first(10).join("\n")
end