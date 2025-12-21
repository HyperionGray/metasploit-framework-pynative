#!/bin/bash

# Test script to verify the Ruby wrapper works
cd /workspace

echo "Testing Ruby wrapper loading..."

# Test 1: Basic loading
ruby -e "
\$LOAD_PATH.unshift('./lib')
begin
  require './lib/msfenv'
  require './tools/password/md5_lookup.rb'
  puts '✓ Ruby wrapper loaded successfully'
rescue => e
  puts '✗ Error loading Ruby wrapper: ' + e.message
  puts e.backtrace.join(\"\n\")
  exit 1
end
"

if [ $? -eq 0 ]; then
  echo "✓ Basic loading test passed"
else
  echo "✗ Basic loading test failed"
  exit 1
fi

# Test 2: Run the actual failing test
echo "Running the actual md5_lookup test..."
bundle exec rspec spec/tools/md5_lookup_spec.rb --format documentation

echo "Test completed."