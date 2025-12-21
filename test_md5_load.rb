#!/usr/bin/env ruby

# Simple test to check if md5_lookup.rb can be loaded

begin
  # Set up the path like the test does
  msfbase = File.expand_path(File.dirname(__FILE__))
  
  # Mock the Metasploit::Framework.root method
  module Metasploit
    module Framework
      def self.root
        Pathname.new(msfbase)
      end
    end
  end
  
  require 'pathname'
  
  # Try to load the file
  load_path = Metasploit::Framework.root.join('tools/password/md5_lookup.rb').to_path
  puts "Attempting to load: #{load_path}"
  
  if File.exist?(load_path)
    puts "File exists, attempting to load..."
    load load_path
    puts "Successfully loaded md5_lookup.rb"
    
    # Test if the classes are defined
    puts "Md5LookupUtility defined: #{defined?(Md5LookupUtility)}"
    puts "Md5LookupUtility::Disclaimer defined: #{defined?(Md5LookupUtility::Disclaimer)}"
    puts "Md5LookupUtility::Md5Lookup defined: #{defined?(Md5LookupUtility::Md5Lookup)}"
    puts "Md5LookupUtility::Driver defined: #{defined?(Md5LookupUtility::Driver)}"
    puts "Md5LookupUtility::OptsConsole defined: #{defined?(Md5LookupUtility::OptsConsole)}"
    
  else
    puts "File does not exist at: #{load_path}"
  end
  
rescue => e
  puts "Error loading file: #{e.class}: #{e.message}"
  puts e.backtrace.join("\n")
end