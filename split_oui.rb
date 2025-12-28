#!/usr/bin/env ruby

# Script to split the OUI file into smaller chunks
require 'fileutils'

def split_oui_file(input_file, output_dir)
  # Create output directory
  FileUtils.mkdir_p(output_dir)
  
  # Read the original file
  content = File.read(input_file)
  
  # Extract the OUI_LIST hash content
  oui_match = content.match(/OUI_LIST = \{(.*?)\}/m)
  unless oui_match
    puts "Could not find OUI_LIST in file"
    return
  end
  
  oui_content = oui_match[1]
  
  # Parse OUI entries
  oui_entries = {}
  oui_content.scan(/"([0-9A-F]{6})" => \[(.*?)\]/) do |mac, data|
    first_char = mac[0]
    oui_entries[first_char] ||= []
    oui_entries[first_char] << "      \"#{mac}\" => [#{data}]"
  end
  
  puts "Found #{oui_entries.values.map(&:length).sum} OUI entries"
  puts "Splitting into #{oui_entries.keys.length} files by first character"
  
  # Create individual OUI files
  oui_entries.each do |first_char, entries|
    filename = File.join(output_dir, "oui_#{first_char.downcase}.rb")
    File.open(filename, 'w') do |f|
      f.puts "# -*- coding: binary -*-"
      f.puts ""
      f.puts "module Rex"
      f.puts "module Oui"
      f.puts ""
      f.puts "  # OUI entries starting with #{first_char}"
      f.puts "  OUI_#{first_char} = {"
      entries.each { |entry| f.puts entry + "," }
      f.puts "    }"
      f.puts ""
      f.puts "end"
      f.puts "end"
    end
    puts "Created #{filename} with #{entries.length} entries"
  end
  
  # Create the new main OUI file
  new_main_file = input_file.gsub('.rb', '_split.rb')
  File.open(new_main_file, 'w') do |f|
    f.puts "# -*- coding: binary -*-"
    f.puts ""
    
    # Require all OUI files
    oui_entries.keys.sort.each do |first_char|
      f.puts "require 'rex/oui/oui_#{first_char.downcase}'"
    end
    f.puts ""
    
    f.puts "module Rex"
    f.puts "module Oui"
    f.puts ""
    f.puts "  def self.lookup_oui_fullname(mac)"
    f.puts "    check_mac(mac)"
    f.puts "    mac = mac.upcase.gsub(':','')[0,6]"
    f.puts "    oui = OUI_LIST[mac]"
    f.puts "    if oui"
    f.puts "      fullname = oui[0]"
    f.puts "      fullname = oui[0] + ' / ' + oui[1] if oui[1] != \"\""
    f.puts "      return fullname"
    f.puts "    else"
    f.puts "      return 'UNKNOWN'"
    f.puts "    end"
    f.puts "  end"
    f.puts ""
    f.puts "  def self.lookup_oui_company_name(mac)"
    f.puts "    check_mac(mac)"
    f.puts "    mac = mac.upcase.gsub(':','')[0,6]"
    f.puts "    oui = OUI_LIST[mac]"
    f.puts "    if oui"
    f.puts "      fullname = oui[0]"
    f.puts "      fullname = oui[1] if oui[1] != \"\""
    f.puts "      return fullname"
    f.puts "    else"
    f.puts "      return 'UNKNOWN'"
    f.puts "    end"
    f.puts "  end"
    f.puts ""
    f.puts "  def self.check_mac(mac)"
    f.puts "    unless mac =~ /(^([A-Fa-f0-9]{2}:){2,5}[A-Fa-f0-9]{2}$)|(^([A-Fa-f0-9]{2}){3,6}$)/"
    f.puts "      raise \"Mac address is not in a correct format\""
    f.puts "    end"
    f.puts "  end"
    f.puts ""
    f.puts "  # Combined OUI list from all split files"
    f.puts "  OUI_LIST = {}"
    
    # Merge all OUI hashes
    oui_entries.keys.sort.each do |first_char|
      f.puts "  OUI_LIST.merge!(OUI_#{first_char})"
    end
    
    f.puts ""
    f.puts "end"
    f.puts "end"
  end
  
  puts "\nOUI split complete!"
  puts "Created new main file: #{new_main_file}"
  puts "Total OUI files: #{oui_entries.keys.length}"
  puts "Total entries: #{oui_entries.values.map(&:length).sum}"
  
  puts "\nBreakdown by first character:"
  oui_entries.sort.each do |first_char, entries|
    puts "  #{first_char}: #{entries.length} entries"
  end
end

if __FILE__ == $0
  input_file = '/workspace/lib/rex/oui.rb'
  output_dir = '/workspace/lib/rex/oui'
  
  split_oui_file(input_file, output_dir)
end