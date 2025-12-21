#!/usr/bin/env ruby

##
# This module requires Metasploit: https://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

#
# This script will allow you to look up MD5 hashes against various online databases.
# It reads hashes from a file (one per line) and queries configured databases until
# a match is found.
#
# Authors:
# Metasploit Framework Team
#
# References:
# Various MD5 lookup services
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

module Md5LookupUtility

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
      load_setting('waiver') == true
    end

    def save_setting(name, value)
      ini = Rex::Parser::Ini.new(@config_path)
      ini['MD5Lookup'] ||= {}
      ini['MD5Lookup'][name] = value
      ini.to_file(@config_path)
    end

    def load_setting(name)
      return nil unless File.exist?(@config_path)
      ini = Rex::Parser::Ini.new(@config_path)
      ini['MD5Lookup'] && ini['MD5Lookup'][name]
    end
  end

  class Md5Lookup

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
    end

    def lookup(hash_value, database)
      LOOKUP_ENDPOINTS.each do |endpoint|
        begin
          uri = URI.parse(endpoint)
          
          # Create HTTP client for this endpoint
          client = Rex::Proto::Http::Client.new(uri.host, uri.port, {}, uri.scheme == 'https')
          
          res = client.request_cgi({
            'uri' => uri.path,
            'method' => 'GET',
            'vars_get' => {
              'database' => database,
              'hash' => hash_value
            }
          })
          
          client.send_recv(res)
          
          next unless res && res.code == 200
          
          result = get_json_result(res)
          return result unless result.empty?
        rescue => e
          # Continue to next endpoint
          next
        end
      end
      ''
    end

    # For testing compatibility - allow mocking of send_request_cgi
    def send_request_cgi(opts)
      # This method is used by tests to mock HTTP requests
      # In real usage, we use the client.request_cgi approach above
      nil
    end

    private

    def get_json_result(response)
      return '' if response.body.nil? || response.body.empty?
      
      begin
        data = JSON.parse(response.body)
        if data['status']
          return data['result'] || ''
        end
      rescue JSON::ParserError
        # Invalid JSON, return empty
      end
      ''
    end
  end

  class Driver
    def initialize(argv = ARGV)
      @options = OptsConsole.parse(argv)
      @output_handle = nil
    end

    def run
      disclaimer = Disclaimer.new
      unless disclaimer.send(:has_waiver?)
        return unless disclaimer.ack
      end

      @output_handle = File.new(@options[:outfile], 'wb') if @options[:outfile]

      get_hash_results(@options[:input], @options[:databases]) do |result|
        puts "Found: #{result[:hash]} = #{result[:cracked_hash]} (from #{result[:credit]})"
        save_result(result) if @output_handle
      end

      @output_handle.close if @output_handle
    end

    private

    def save_result(result)
      @output_handle.write("#{result[:hash]} = #{result[:cracked_hash]}\n")
    end

    def get_hash_results(input_file, databases)
      search_engine = Md5Lookup.new
      
      extract_hashes(input_file) do |hash_value|
        databases.each do |database|
          cracked_hash = search_engine.lookup(hash_value, database)
          unless cracked_hash.empty?
            result = {
              hash: hash_value,
              cracked_hash: cracked_hash,
              credit: database
            }
            yield result
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
      value.length == 32 && value.match?(/\A[a-fA-F0-9]+\z/)
    end
  end

  class OptsConsole
    def self.parse(args)
      options = {}
      
      parser = OptionParser.new do |opts|
        opts.banner = "Usage: #{$0} [options]"
        
        opts.on('-i', '--input FILE', 'Input file containing MD5 hashes') do |file|
          raise OptionParser::MissingArgument, 'Input file does not exist' unless File.exist?(file)
          options[:input] = file
        end
        
        opts.on('-d', '--databases DATABASES', 'Comma-separated database names') do |dbs|
          options[:databases] = extract_db_names(dbs)
        end
        
        opts.on('-o', '--outfile FILE', 'Output file for results') do |file|
          options[:outfile] = file
        end
        
        opts.on('-h', '--help', 'Show this help message') do
          puts opts
          exit
        end
      end
      
      parser.parse!(args)
      
      raise OptionParser::MissingArgument, 'Input file is required' unless options[:input]
      
      options[:databases] ||= get_database_names
      options
    end

    def self.extract_db_names(list)
      symbols = list.split(',').map(&:strip)
      if symbols.include?('all')
        return get_database_names
      end
      
      symbols.map do |symbol|
        Md5Lookup::DATABASES[symbol]
      end.compact
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