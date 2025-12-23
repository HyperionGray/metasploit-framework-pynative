#!/usr/bin/env ruby

# Quick test to check if the Ruby wrapper loads correctly
$LOAD_PATH.unshift('/workspace/lib')

begin
  require '/workspace/lib/msfenv'
  require '/workspace/tools/password/md5_lookup.rb'
  puts "✓ Ruby wrapper loaded successfully"
  
  # Test basic class instantiation
  disclaimer = Md5LookupUtility::Disclaimer.new
  puts "✓ Disclaimer class instantiated"
  
  lookup = Md5LookupUtility::Md5Lookup.new
  puts "✓ Md5Lookup class instantiated"
  
  driver = Md5LookupUtility::Driver.new
  puts "✓ Driver class instantiated"
  
  puts "✓ All classes loaded successfully"
  
rescue => e
  puts "✗ Error loading Ruby wrapper: #{e.message}"
  puts e.backtrace.join("\n")
end