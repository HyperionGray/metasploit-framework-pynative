#!/usr/bin/env ruby

# Simple script to validate the MSF module syntax
require 'pathname'

# Add the framework lib path
framework_root = Pathname.new(__FILE__).parent.parent
lib_path = framework_root.join('lib')
$LOAD_PATH.unshift(lib_path.to_s) unless $LOAD_PATH.include?(lib_path.to_s)

begin
  # Try to load the basic MSF requirements
  require 'msf/core'
  require 'msf/base'
  
  # Load our module
  module_path = framework_root.join('modules', 'exploits', 'freebsd', 'rtsold_resolvconf_command_injection.rb')
  
  if File.exist?(module_path)
    puts "[+] Module file exists: #{module_path}"
    
    # Try to load the module
    begin
      load module_path.to_s
      puts "[+] Module loaded successfully"
      
      # Try to instantiate the module
      mod = MetasploitModule.new
      puts "[+] Module instantiated successfully"
      puts "[+] Module name: #{mod.name}"
      puts "[+] Module description: #{mod.description[0..100]}..."
      puts "[+] Module rank: #{mod.rank}"
      puts "[+] Module platform: #{mod.platform}"
      puts "[+] Module targets: #{mod.targets.length}"
      
    rescue => e
      puts "[-] Error loading/instantiating module: #{e.message}"
      puts e.backtrace.first(5).join("\n")
    end
  else
    puts "[-] Module file not found: #{module_path}"
  end
  
rescue => e
  puts "[-] Error setting up framework: #{e.message}"
  puts "This is expected if MSF dependencies are not fully available"
end

puts "\n[*] Basic syntax validation complete"