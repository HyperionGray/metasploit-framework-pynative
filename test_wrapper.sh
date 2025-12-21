#!/bin/bash

cd /workspace

echo "Testing Ruby wrapper loading..."
ruby test_md5_load.rb

echo ""
echo "Testing if the original test can load the file..."
ruby -e "
\$LOAD_PATH.unshift(File.join(Dir.pwd, 'lib'))
begin
  load File.join(Dir.pwd, 'tools/password/md5_lookup.rb')
  puts '✓ Test file can load md5_lookup.rb'
rescue => e
  puts '✗ Error loading: ' + e.message
  puts e.backtrace.first(3)
end
"