#!/usr/bin/env ruby

# Very basic test - just try to load the file
puts "Attempting to load md5_lookup.rb..."

begin
  # Just try to load the file without any dependencies first
  content = File.read('/workspace/tools/password/md5_lookup.rb')
  puts "✓ File exists and is readable (#{content.length} bytes)"
  
  # Check for syntax errors
  eval("BEGIN { return }; #{content}")
  puts "✓ No syntax errors detected"
  
rescue SyntaxError => e
  puts "✗ Syntax error: #{e.message}"
  exit 1
rescue => e
  puts "✗ Error: #{e.message}"
  exit 1
end

puts "Basic file validation passed!"