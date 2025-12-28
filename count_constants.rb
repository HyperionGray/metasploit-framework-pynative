#!/usr/bin/env ruby

# Quick count of constants
def count_constants(file_path)
  count = 0
  File.readlines(file_path).each do |line|
    if line.match(/^\s*win_const_mgr\.add_const\('([^']+)',(.+)\)/)
      count += 1
    end
  end
  count
end

file_path = '/workspace/lib/rex/post/meterpreter/extensions/stdapi/railgun/def/windows/api_constants.rb'
puts "Total constants in file: #{count_constants(file_path)}"