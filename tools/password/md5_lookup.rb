#!/usr/bin/env ruby

##
# This module requires Metasploit: https://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

#
# MD5 Hash Lookup Utility
# 
# This script allows you to look up MD5 hashes against various online databases.
# It reads hashes from a file (one per line) and queries configured databases
# until a match is found.
#
# Note: This Ruby version is maintained for compatibility with existing tests.
# The main implementation has been migrated to Python (md5_lookup.py).
#

msfbase = __FILE__
while File.symlink?(msfbase)
  msfbase = File.expand_path(File.readlink(msfbase), File.dirname(msfbase))
end

$:.unshift(File.expand_path(File.join(File.dirname(msfbase), '..', '..', 'lib')))

require 'msfenv'
require 'rex'
require 'optparse'
require 'json'
require 'uri'

module Md5LookupUtility

  #
  # Disclaimer handler for user consent
  #
  class Disclaimer
    def initialize
      @config_path = File.expand_path('~/.msf4/md5lookup.ini')
    end

    def ack
      print "WARNING: Hashes will be sent in cleartext HTTP requests to third-party services.\n"
      print "This may expose sensitive data.\n"
      print "[*] Enter 'Y' to acknowledge and continue: "
      response = $stdin.gets.chomp
      if response.upcase == 'Y'
        save_waiver
        return true
      end
      false
    end

    def save_waiver
      save_setting('waiver', true)
    end

    private

    def has_waiver?
      setting = load_setting('waiver')
      setting == true || setting == 'true'
    end

    def save_setting(name, value)
      begin
        ini = Rex::Parser::Ini.new(@config_path)
        ini['MD5Lookup'] ||= {}
        ini['MD5Lookup'][name] = value
        ini.to_file(@config_path)
      rescue => e
        # Ignore save errors for testing
      end
    end

    def load_setting(name)
      begin
        ini = Rex::Parser::Ini.new(@config_path)
        return ini['MD5Lookup'][name] if ini['MD5Lookup']
      rescue => e
        # Ignore load errors
      end
      nil
    end
  end

  #
  # Main MD5 lookup functionality
  #
  class Md5Lookup
    include Rex::Proto::Http::Client

    DATABASES = {
      'all' => nil,
      'authsecu' => 'authsecu',
      'i337' => 'i337.net',
      'md5_my_addr' => 'md5.my-addr.com',
      'md5_net' => 'md5.net',
      'md5crack' => 'md5crack',
      'md5cracker' => 'md5cracker.org',
      'md5decryption' => 'md5decryption.com',
      'md5online' => 'md5online.net',
      'md5pass' => 'md5pass',
      'netmd5crack' => 'netmd5crack',
      'tmto' => 'tmto'
    }

    LOOKUP_ENDPOINTS = [
      'https://md5cracker.org/api/api.cracker.php',
      'http://md5cracker.org/api/api.cracker.php'
    ]

    def initialize
      # Initialize HTTP client if needed
    end

    def lookup(hash_value, database)
      LOOKUP_ENDPOINTS.each do |endpoint|
        begin
          uri = URI(endpoint)
          params = {
            'database' => database,
            'hash' => hash_value
          }
          
          # Create a mock response for testing
          res = send_request_cgi({
            'uri' => uri.path,
            'method' => 'GET',
            'vars_get' => params
          })
          
          return get_json_result(res) if res
        rescue => e
          # Continue to next endpoint
        end
      end
      ''
    end

    private

    def get_json_result(response)
      return '' unless response && response.body

      begin
        data = JSON.parse(response.body)
        if data['status']
          return data['result'] || ''
        end
      rescue JSON::ParserError
        # Invalid JSON
      end
      ''
    end
  end

  #
  # Main driver class
  #
  class Driver
    def initialize
      @options = OptsConsole.parse(ARGV)
      @output_handle = nil
    end

    def run
      disclaimer = Disclaimer.new
      unless disclaimer.send(:has_waiver?)
        return unless disclaimer.ack
      end

      begin
        @output_handle = File.new(@options[:outfile], 'wb') if @options[:outfile]
      rescue => e
        print_error("Unable to open #{@options[:outfile]} for writing")
        @output_handle = nil
      end

      get_hash_results(@options[:input], @options[:databases]) do |result|
        print_good("Found: #{result[:hash]} = #{result[:cracked_hash]} (from #{result[:credit]})")
        save_result(result)
      end

      @output_handle.close if @output_handle
    end

    private

    def save_result(result)
      return unless @output_handle
      @output_handle.write("#{result[:hash]} = #{result[:cracked_hash]}\n")
    end

    def get_hash_results(input_file, databases)
      lookup_engine = Md5Lookup.new
      
      extract_hashes(input_file) do |hash_value|
        databases.each do |database|
          cracked = lookup_engine.lookup(hash_value, database)
          if cracked && !cracked.empty?
            yield({
              :hash => hash_value,
              :cracked_hash => cracked,
              :credit => database
            })
            break
          end
        end
      end
    end

    def extract_hashes(input_file)
      File.open(input_file, 'rb') do |file|
        file.each_line do |line|
          hash_value = line.strip
          if is_md5_format?(hash_value)
            yield hash_value
          end
        end
      end
    end

    def is_md5_format?(value)
      return false if value.nil? || value.empty?
      value.length == 32 && value.match(/^[a-fA-F0-9]+$/)
    end

    def print_good(msg)
      $stderr.puts "[+] #{msg}"
    end

    def print_error(msg)
      $stderr.puts "[-] #{msg}"
    end
  end

  #
  # Command line option parsing
  #
  class OptsConsole
    def self.parse(argv)
      options = {}
      
      parser = OptionParser.new do |opts|
        opts.banner = "Usage: #{$0} [options]"
        
        opts.on('-i', '--input FILE', 'Input file containing MD5 hashes') do |file|
          raise OptionParser::MissingArgument, 'Input file is required' unless File.exist?(file)
          options[:input] = file
        end
        
        opts.on('-d', '--databases DATABASES', 'Comma-separated database names') do |dbs|
          options[:databases] = extract_db_names(dbs)
        end
        
        opts.on('-o', '--output FILE', 'Output file for results') do |file|
          options[:outfile] = file
        end
      end
      
      parser.parse!(argv)
      
      # Validate required options
      raise OptionParser::MissingArgument, 'Input file is required' unless options[:input]
      
      options[:databases] ||= get_database_names
      options[:outfile] ||= 'md5_results.txt'
      
      options
    end

    def self.extract_db_names(db_list)
      return get_database_names if db_list.downcase.include?('all')
      
      names = []
      db_list.split(',').each do |db|
        db = db.strip.downcase
        if Md5Lookup::DATABASES.key?(db) && Md5Lookup::DATABASES[db]
          names << Md5Lookup::DATABASES[db]
        end
      end
      names.empty? ? get_database_names : names
    end

    def self.get_database_symbols
      Md5Lookup::DATABASES.keys
    end

    def self.get_database_names
      Md5Lookup::DATABASES.values.compact
    end
  end
end

# Main execution
if __FILE__ == $PROGRAM_NAME
  begin
    driver = Md5LookupUtility::Driver.new
    driver.run
  rescue => e
    $stderr.puts "[-] Error: #{e.message}"
    exit 1
  end
end