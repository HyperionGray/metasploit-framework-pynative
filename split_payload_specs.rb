#!/usr/bin/env ruby

# Script to split payload specs by platform
require 'fileutils'

def extract_platform_from_payload(payload_name)
  # Extract platform from payload reference name
  parts = payload_name.split('/')
  return parts[0] if parts.length > 0
  'unknown'
end

def split_payload_specs(input_file, output_dir)
  # Create output directory
  FileUtils.mkdir_p(output_dir)
  
  # Read the file
  content = File.read(input_file)
  
  # Extract the header and footer
  header_match = content.match(/^(.*?)(  context '[^']+' do.*)/m)
  unless header_match
    puts "Could not parse file structure"
    return
  end
  
  header = header_match[1]
  specs_content = header_match[2]
  
  # Parse individual test contexts
  contexts = {}
  current_context = nil
  current_content = []
  
  specs_content.split("\n").each do |line|
    if line.match(/^  context '([^']+)' do/)
      # Save previous context if exists
      if current_context
        platform = extract_platform_from_payload(current_context)
        contexts[platform] ||= []
        contexts[platform] << current_content.join("\n")
      end
      
      # Start new context
      current_context = $1
      current_content = [line]
    elsif line.match(/^  end$/) && current_context
      # End of context
      current_content << line
      platform = extract_platform_from_payload(current_context)
      contexts[platform] ||= []
      contexts[platform] << current_content.join("\n")
      current_context = nil
      current_content = []
    elsif current_context
      current_content << line
    end
  end
  
  puts "Found #{contexts.values.map(&:length).sum} payload tests"
  puts "Splitting into #{contexts.keys.length} platform files"
  
  # Create platform-specific spec files
  contexts.each do |platform, specs|
    filename = File.join(output_dir, "#{platform}_payloads_spec.rb")
    File.open(filename, 'w') do |f|
      f.puts "require 'spec_helper'"
      f.puts ""
      f.puts "RSpec.describe 'modules/payloads/#{platform}', :content do"
      f.puts "  modules_pathname = Pathname.new(__FILE__).parent.parent.parent.parent.join('modules')"
      f.puts ""
      f.puts "  include_context 'untested payloads', modules_pathname: modules_pathname"
      f.puts ""
      specs.each { |spec| f.puts spec; f.puts "" }
      f.puts "end"
    end
    puts "Created #{filename} with #{specs.length} tests"
  end
  
  # Create a main spec file that includes all platform specs
  main_spec_file = input_file.gsub('.rb', '_split.rb')
  File.open(main_spec_file, 'w') do |f|
    f.puts "require 'spec_helper'"
    f.puts ""
    f.puts "# Main payload specs file - includes all platform-specific specs"
    f.puts "# Original monolithic file had #{contexts.values.map(&:length).sum} tests and has been split into #{contexts.keys.length} platform files."
    f.puts ""
    
    contexts.keys.sort.each do |platform|
      f.puts "require_relative 'payloads/#{platform}_payloads_spec'"
    end
  end
  
  puts "\nPayload specs split complete!"
  puts "Created main spec file: #{main_spec_file}"
  puts "Total platform files: #{contexts.keys.length}"
  puts "Total tests: #{contexts.values.map(&:length).sum}"
  
  puts "\nBreakdown by platform:"
  contexts.sort.each do |platform, specs|
    puts "  #{platform}: #{specs.length} tests"
  end
end

if __FILE__ == $0
  input_file = '/workspace/spec/modules/payloads_spec.rb'
  output_dir = '/workspace/spec/modules/payloads'
  
  split_payload_specs(input_file, output_dir)
end