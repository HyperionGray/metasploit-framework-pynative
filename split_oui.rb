#!/usr/bin/env ruby

# Script to split the large OUI file into smaller chunks
# This will read the original oui.rb file and split the OUI_LIST hash
# into separate files based on the first character of the MAC address

require 'fileutils'

# Read the original file
original_file = '/workspace/lib/rex/oui.rb'
lines = File.readlines(original_file)

# Find the start and end of the OUI_LIST hash
start_idx = lines.find_index { |line| line.include?('OUI_LIST = {') }
end_idx = lines.rindex { |line| line.strip == '}' }

# Parse the entries
entries = {}
(start_idx + 1...end_idx).each do |i|
  line = lines[i].strip
  next if line.empty?
  
  # Match lines like: "000000" => ["Xerox", "XEROX CORPORATION"],
  if match = line.match(/"([0-9A-F]{6})" => \[(.*?)\],?$/)
    mac = match[1]
    data = match[2]
    first_char = mac[0]
    entries[first_char] ||= []
    entries[first_char] << [mac, data]
  end
end

# Create directory for split files
FileUtils.mkdir_p('/workspace/lib/rex/oui')

# Generate split files
entries.each do |first_char, mac_entries|
  filename = "/workspace/lib/rex/oui/data_#{first_char.downcase}.rb"
  
  File.open(filename, 'w') do |f|
    f.puts "# -*- coding: binary -*-"
    f.puts ""
    f.puts "module Rex"
    f.puts "module Oui"
    f.puts ""
    f.puts "  # OUI data for MAC addresses starting with #{first_char}"
    f.puts "  OUI_DATA_#{first_char} = {"
    
    mac_entries.each do |mac, data|
      f.puts "    \"#{mac}\" => [#{data}],"
    end
    
    f.puts "  }"
    f.puts ""
    f.puts "end"
    f.puts "end"
  end
  
  puts "Created #{filename} with #{mac_entries.length} entries"
end

puts "Split complete!"