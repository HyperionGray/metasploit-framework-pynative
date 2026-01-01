#!/usr/bin/env ruby

# Script to analyze Windows API constants and categorize them for splitting

require 'set'

# Read the api_constants.rb file
file_path = '/workspace/lib/rex/post/meterpreter/extensions/stdapi/railgun/def/windows/api_constants.rb'
content = File.read(file_path)

# Extract all constants
constants = []
content.scan(/win_const_mgr\.add_const\('([^']+)',/) do |match|
  constants << match[0]
end

puts "Total constants found: #{constants.length}"

# Analyze prefixes
prefix_counts = Hash.new(0)
constants.each do |const|
  # Extract prefix (up to first underscore or first 3-4 characters)
  if const.include?('_')
    prefix = const.split('_')[0]
  else
    prefix = const[0..3]
  end
  prefix_counts[prefix] += 1
end

# Sort by count and show top prefixes
puts "\nTop 50 prefixes by count:"
prefix_counts.sort_by { |k, v| -v }.first(50).each do |prefix, count|
  puts "#{prefix}: #{count}"
end

# Analyze common categories
categories = {
  'ERROR' => constants.select { |c| c.start_with?('ERROR_') },
  'WM' => constants.select { |c| c.start_with?('WM_') },
  'VK' => constants.select { |c| c.start_with?('VK_') },
  'LANG' => constants.select { |c| c.start_with?('LANG_') },
  'SUBLANG' => constants.select { |c| c.start_with?('SUBLANG_') },
  'DNS' => constants.select { |c| c.start_with?('DNS_') },
  'SQL' => constants.select { |c| c.start_with?('SQL_') },
  'RPC' => constants.select { |c| c.start_with?('RPC_') },
  'INTERNET' => constants.select { |c| c.start_with?('INTERNET_') },
  'WINHTTP' => constants.select { |c| c.start_with?('WINHTTP_') },
  'CERT' => constants.select { |c| c.start_with?('CERT_') },
  'CRYPT' => constants.select { |c| c.start_with?('CRYPT') },
  'SECURITY' => constants.select { |c| c.start_with?('SECURITY_') },
  'SERVICE' => constants.select { |c| c.start_with?('SERVICE_') },
  'FILE' => constants.select { |c| c.start_with?('FILE_') },
  'REG' => constants.select { |c| c.start_with?('REG') },
  'KEY' => constants.select { |c| c.start_with?('KEY_') },
  'GENERIC' => constants.select { |c| c.start_with?('GENERIC_') },
  'STANDARD' => constants.select { |c| c.start_with?('STANDARD_') },
  'PROCESS' => constants.select { |c| c.start_with?('PROCESS_') },
  'THREAD' => constants.select { |c| c.start_with?('THREAD_') },
  'TOKEN' => constants.select { |c| c.start_with?('TOKEN_') },
  'IMAGE' => constants.select { |c| c.start_with?('IMAGE_') },
  'DEBUG' => constants.select { |c| c.start_with?('DEBUG_') },
  'EXCEPTION' => constants.select { |c| c.start_with?('EXCEPTION_') }
}

puts "\nCategory analysis:"
categories.each do |category, consts|
  puts "#{category}: #{consts.length} constants" if consts.length > 0
end

# Find uncategorized constants
categorized = Set.new
categories.each { |_, consts| categorized.merge(consts) }
uncategorized = constants - categorized.to_a

puts "\nUncategorized constants: #{uncategorized.length}"
puts "Sample uncategorized (first 20):"
uncategorized.first(20).each { |c| puts "  #{c}" }