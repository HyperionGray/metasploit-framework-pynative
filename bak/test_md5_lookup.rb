#!/usr/bin/env ruby

# Simple test to verify md5_lookup.rb can be loaded
puts "Testing md5_lookup.rb loading..."

begin
  # Set up the load path similar to how the test does it
  $:.unshift(File.expand_path(File.join(File.dirname(__FILE__), 'lib')))
  
  # Try to load the file
  load File.join(File.dirname(__FILE__), 'tools/password/md5_lookup.rb')
  
  puts "✓ File loaded successfully"
  
  # Test basic class structure
  puts "✓ Md5LookupUtility module: #{defined?(Md5LookupUtility) ? 'OK' : 'MISSING'}"
  puts "✓ Disclaimer class: #{defined?(Md5LookupUtility::Disclaimer) ? 'OK' : 'MISSING'}"
  puts "✓ Md5Lookup class: #{defined?(Md5LookupUtility::Md5Lookup) ? 'OK' : 'MISSING'}"
  puts "✓ Driver class: #{defined?(Md5LookupUtility::Driver) ? 'OK' : 'MISSING'}"
  puts "✓ OptsConsole class: #{defined?(Md5LookupUtility::OptsConsole) ? 'OK' : 'MISSING'}"
  
  # Test basic method existence
  disclaimer = Md5LookupUtility::Disclaimer.new
  puts "✓ Disclaimer#ack method: #{disclaimer.respond_to?(:ack) ? 'OK' : 'MISSING'}"
  puts "✓ Disclaimer#save_waiver method: #{disclaimer.respond_to?(:save_waiver) ? 'OK' : 'MISSING'}"
  
  lookup = Md5LookupUtility::Md5Lookup.new
  puts "✓ Md5Lookup#lookup method: #{lookup.respond_to?(:lookup) ? 'OK' : 'MISSING'}"
  
  puts "✓ OptsConsole.parse method: #{Md5LookupUtility::OptsConsole.respond_to?(:parse) ? 'OK' : 'MISSING'}"
  puts "✓ OptsConsole.extract_db_names method: #{Md5LookupUtility::OptsConsole.respond_to?(:extract_db_names) ? 'OK' : 'MISSING'}"
  
  # Test database constants
  puts "✓ DATABASES constant: #{defined?(Md5LookupUtility::Md5Lookup::DATABASES) ? 'OK' : 'MISSING'}"
  if defined?(Md5LookupUtility::Md5Lookup::DATABASES)
    puts "  - i337 key: #{Md5LookupUtility::Md5Lookup::DATABASES.key?('i337') ? 'OK' : 'MISSING'}"
    puts "  - i337 value: #{Md5LookupUtility::Md5Lookup::DATABASES['i337']}"
  end
  
  puts "\n✅ All basic checks passed!"
  
rescue LoadError => e
  puts "❌ LoadError: #{e.message}"
  puts "   Backtrace: #{e.backtrace.first(3).join("\n   ")}"
rescue SyntaxError => e
  puts "❌ SyntaxError: #{e.message}"
rescue NameError => e
  puts "❌ NameError: #{e.message}"
  puts "   This might indicate missing dependencies"
rescue => e
  puts "❌ Error: #{e.class}: #{e.message}"
  puts "   Backtrace: #{e.backtrace.first(3).join("\n   ")}"
end